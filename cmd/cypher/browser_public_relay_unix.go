//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Socket cleanup uses its held directory and recorded inode. The path lock
// remains held until cleanup finishes; replacements are never removed.
type publicRelaySocket struct {
	*net.UnixListener
	dir      *os.File
	lock     *os.File
	leaf     string
	stat     unix.Stat_t
	owned    bool
	once     sync.Once
	closeErr error
}

func resolvePublicRelaySocketPath(configPath, socketPath string) (string, error) {
	if socketPath == "auto" {
		name := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
		return filepath.Join(filepath.Dir(configPath), name+".sock"), nil
	}
	return socketPath, nil
}

func validatePublicRelaySocketPath(path string) error {
	dir, _, err := publicRelayParent(path, true)
	if err == nil {
		err = dir.Close()
	}
	return err
}

func listenPublicRelaySocket(path string) (net.Listener, error) {
	dir, leaf, err := publicRelayParent(path, true)
	if err != nil {
		return nil, err
	}
	lock, err := lockPublicRelaySocket(dir, leaf)
	if err != nil {
		dir.Close()
		return nil, err
	}
	if err := preparePublicRelaySocketPath(dir, leaf, path, net.DialTimeout); err != nil {
		dir.Close()
		lock.Close()
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		dir.Close()
		lock.Close()
		return nil, fmt.Errorf("cannot bind public-header Unix socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	owned := &publicRelaySocket{UnixListener: listener, dir: dir, lock: lock, leaf: leaf}
	if err := unix.Fstatat(int(dir.Fd()), leaf, &owned.stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || owned.stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, errors.Join(errors.New("cannot identify owned public-header socket"), owned.Close())
	}
	owned.owned = true
	if err := unix.Fchmodat(int(dir.Fd()), leaf, 0600, 0); err != nil {
		return nil, errors.Join(errors.New("cannot restrict public-header socket permissions"), owned.Close())
	}
	return owned, nil
}

// A persistent lock beside the socket serializes users of the same socketPath,
// regardless of datadir, including the bind/listen window and Close cleanup.
// Never unlink the lock file: another opener could otherwise lock a different
// inode while the current owner still holds its lock. A crash releases flock.
func lockPublicRelaySocket(dir *os.File, leaf string) (*os.File, error) {
	name := leaf + ".lock"
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open public-header socket lock: %w", err)
	}
	lock := os.NewFile(uintptr(fd), name)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 || stat.Nlink != 1 {
		lock.Close()
		return nil, errors.New("public-header socket lock must be an owner-only regular file without hard links")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("cannot acquire public-header socket path lock: %w", err)
	}
	var now unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		now.Dev != stat.Dev || now.Ino != stat.Ino || now.Mode&unix.S_IFMT != unix.S_IFREG ||
		now.Uid != uint32(os.Geteuid()) || now.Mode&0077 != 0 || now.Nlink != 1 {
		lock.Close()
		return nil, errors.New("public-header socket lock changed; replacement was preserved")
	}
	return lock, nil
}

// The caller holds the path lock. Only a refused connection to an unchanged,
// same-user socket permits reclamation; every ambiguous failure preserves it.
// dial is passed explicitly so tests can replace the path during the probe.
func preparePublicRelaySocketPath(dir *os.File, leaf, path string, dial func(string, string, time.Duration) (net.Conn, error)) error {
	var existing unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), leaf, &existing, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot inspect public-header socket path: %w", err)
	}
	if existing.Mode&unix.S_IFMT != unix.S_IFSOCK || existing.Uid != uint32(os.Geteuid()) {
		return errors.New("public-header socket path must be a Unix socket owned by the current user; existing path was preserved")
	}
	conn, err := dial("unix", path, time.Second)
	if err == nil {
		conn.Close()
		return errors.New("public-header socket is in use; existing listener was preserved")
	}
	var probeErr net.Error
	if (errors.As(err, &probeErr) && probeErr.Timeout()) || !errors.Is(err, unix.ECONNREFUSED) {
		return fmt.Errorf("cannot establish that public-header socket is stale; existing path was preserved: %w", err)
	}
	var now unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), leaf, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		now.Dev != existing.Dev || now.Ino != existing.Ino || now.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		now.Uid != uint32(os.Geteuid()) {
		return errors.New("public-header socket changed during stale check; replacement was preserved")
	}
	if err := unix.Unlinkat(int(dir.Fd()), leaf, 0); err != nil {
		return fmt.Errorf("cannot reclaim stale public-header socket: %w", err)
	}
	return nil
}

func (s *publicRelaySocket) Close() error {
	s.once.Do(func() {
		s.closeErr = s.UnixListener.Close()
		if errors.Is(s.closeErr, net.ErrClosed) {
			s.closeErr = nil
		}
		if s.owned {
			var now unix.Stat_t
			err := unix.Fstatat(int(s.dir.Fd()), s.leaf, &now, unix.AT_SYMLINK_NOFOLLOW)
			if err == nil && now.Dev == s.stat.Dev && now.Ino == s.stat.Ino && now.Mode&unix.S_IFMT == unix.S_IFSOCK {
				s.closeErr = errors.Join(s.closeErr, unix.Unlinkat(int(s.dir.Fd()), s.leaf, 0))
			} else if err != unix.ENOENT {
				s.closeErr = errors.Join(s.closeErr, errors.New("public-header socket changed; replacement was preserved"))
			}
		}
		s.closeErr = errors.Join(s.closeErr, s.dir.Close())
		// Closing the descriptor releases flock after all socket cleanup is done.
		s.closeErr = errors.Join(s.closeErr, s.lock.Close())
	})
	return s.closeErr
}

// Open directory components without following links. The final socket directory
// must be precreated, owned by this process user, and inaccessible to others.
func publicRelayParent(path string, private bool) (*os.File, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, "", errors.New("absolute canonical public-header paths are required")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", errors.New("cannot open public-header path root")
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, "", errors.New("public-header parent directories must exist without symbolic links")
		}
		fd = next
		var ancestor unix.Stat_t
		if err := unix.Fstat(fd, &ancestor); err != nil ||
			(ancestor.Uid != 0 && ancestor.Uid != uint32(os.Geteuid())) ||
			(ancestor.Mode&0022 != 0 && ancestor.Mode&unix.S_ISVTX == 0) {
			unix.Close(fd)
			return nil, "", errors.New("public-header parent directories must not permit untrusted replacement")
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || (private && (stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0)) {
		unix.Close(fd)
		return nil, "", errors.New("public-header socket directory must be owner-only")
	}
	return os.NewFile(uintptr(fd), filepath.Dir(path)), parts[len(parts)-1], nil
}

func readPublicRelayFile(path string, secret bool) ([]byte, error) {
	dir, leaf, err := publicRelayParent(path, false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot open public-header configuration or key without symbolic links")
	}
	f := os.NewFile(uintptr(fd), leaf)
	defer f.Close()
	var stat unix.Stat_t
	forbidden := uint32(0022)
	if secret {
		forbidden = 0077
	}
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || uint32(stat.Mode)&forbidden != 0 || stat.Size > 4096 {
		return nil, errors.New("public-header files must be bounded owner-controlled regular files; signing keys must be owner-only")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, errors.New("public-header file exceeds its read budget")
	}
	return raw, nil
}
