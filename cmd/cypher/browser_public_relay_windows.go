//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const publicRelayPipePrefix = `\\.\pipe\`

func resolvePublicRelaySocketPath(configPath, socketPath string) (string, error) {
	if socketPath != "auto" {
		return socketPath, validatePublicRelaySocketPath(socketPath)
	}
	if err := validatePublicRelayFilePath(configPath); err != nil {
		return "", err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", errors.New("cannot determine browser relay pipe owner")
	}
	// Pipe names are case-insensitive. Including the config path permits separate
	// instances for one user, while the SID separates different local users.
	digest := sha256.Sum256([]byte("cypher-browser-relay-pipe-v1\x00" + user.User.Sid.String() + "\x00" + strings.ToLower(configPath)))
	return publicRelayPipePrefix + "cypher-browser-relay-" + hex.EncodeToString(digest[:16]), nil
}

func validatePublicRelaySocketPath(path string) error {
	if !strings.HasPrefix(path, publicRelayPipePrefix) {
		return errors.New("browser relay requires a local \\\\.\\pipe\\ endpoint")
	}
	name := strings.TrimPrefix(path, publicRelayPipePrefix)
	if len(name) == 0 || len(name) > 128 {
		return errors.New("browser relay pipe name must contain 1 to 128 ASCII letters, digits, underscores or hyphens")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return errors.New("browser relay pipe name must contain only ASCII letters, digits, underscores or hyphens")
		}
	}
	return nil
}

func listenPublicRelaySocket(path string) (net.Listener, error) {
	if err := validatePublicRelaySocketPath(path); err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, errors.New("cannot determine browser relay pipe owner")
	}
	sid := user.User.Sid.String()
	// go-winio reserves the first instance with FILE_CREATE and always sets
	// FILE_PIPE_REJECT_REMOTE_CLIENTS. Its overlapped I/O supports net.Conn
	// deadlines and Close cancellation for HTTP and WebSocket shutdown.
	return winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: "O:" + sid + "D:P(A;;GA;;;" + sid + ")",
		InputBufferSize:    16 << 10,
		OutputBufferSize:   16 << 10,
	})
}

func validatePublicRelayFilePath(path string) error {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.Contains(path, "/") || len(path) <= 3 || !filepath.IsLocal(path[3:]) {
		return errors.New("browser relay files require absolute canonical local-drive paths")
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if strings.TrimRight(part, ". ") != part {
			return errors.New("browser relay file path contains an ambiguous component")
		}
	}
	return nil
}

// Administrators and SYSTEM can already take ownership of local files. The
// Windows servicing identity owns some drive roots and is trusted for ancestor
// checks only. Signing/config files themselves must belong to the process user.
func publicRelayPrivilegedSID(sid *windows.SID, ancestor bool) bool {
	return sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		ancestor && sid.String() == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

func validatePublicRelaySecurity(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, ancestor, secret bool) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !(owner.Equals(user) || ancestor && publicRelayPrivilegedSID(owner, true)) {
		return errors.New("browser relay file owner is not trusted")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("browser relay files require an explicit restrictive DACL")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return errors.New("cannot inspect browser relay file permissions")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || int(ace.Header.AceSize) < int(unsafe.Offsetof(ace.SidStart))+8 {
			return errors.New("unsupported browser relay file permission entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len() > int(ace.Header.AceSize)-int(unsafe.Offsetof(ace.SidStart)) {
			return errors.New("invalid browser relay file permission identity")
		}
		if sid.Equals(user) || publicRelayPrivilegedSID(sid, ancestor) {
			continue
		}
		// Creating siblings on a shared ancestor is harmless. Deleting children
		// or changing the ancestor's ownership, DACL or attributes is not.
		forbidden := uint32(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA)
		if ancestor {
			forbidden |= 0x40 // FILE_DELETE_CHILD
		} else {
			forbidden |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
		}
		if uint32(ace.Mask)&forbidden != 0 || secret && ace.Mask != 0 {
			return errors.New("browser relay files permit untrusted access; keys require an owner-only DACL (SYSTEM and Administrators are trusted)")
		}
	}
	return nil
}

func openPublicRelayFileHandle(path string, user *windows.SID, directory, secret bool) (windows.Handle, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	access, share := uint32(windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL), uint32(windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if !directory {
		access, share = windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ
	}
	// No FILE_SHARE_DELETE: retain each ancestor until the leaf read finishes,
	// so a directory cannot be renamed/replaced between component checks.
	h, err := windows.CreateFile(ptr, access, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return windows.InvalidHandle, errors.New("cannot open browser relay file path safely")
	}
	fail := func() (windows.Handle, error) {
		windows.CloseHandle(h)
		return windows.InvalidHandle, errors.New("browser relay files must be bounded owner-controlled regular files without reparse points")
	}
	var info windows.ByHandleFileInformation
	fileType, typeErr := windows.GetFileType(h)
	if typeErr != nil || fileType != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(h, &info) != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory ||
		!directory && (info.FileSizeHigh != 0 || info.FileSizeLow > 4096) {
		return fail()
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fail()
	}
	if err := validatePublicRelaySecurity(sd, user, directory, secret); err != nil {
		windows.CloseHandle(h)
		return windows.InvalidHandle, err
	}
	return h, nil
}

func readPublicRelayFile(path string, secret bool) ([]byte, error) {
	if err := validatePublicRelayFilePath(path); err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, errors.New("cannot determine browser relay file owner")
	}
	parts := strings.Split(path[3:], `\`)
	parents := make([]windows.Handle, 0, len(parts))
	defer func() {
		for i := len(parents) - 1; i >= 0; i-- {
			windows.CloseHandle(parents[i])
		}
	}()
	prefix := path[:3]
	for i := 0; i < len(parts); i++ {
		if i > 0 {
			prefix = filepath.Join(prefix, parts[i-1])
		}
		h, err := openPublicRelayFileHandle(prefix, user.User.Sid, true, false)
		if err != nil {
			return nil, err
		}
		parents = append(parents, h)
	}
	h, err := openPublicRelayFileHandle(path, user.User.Sid, false, secret)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), filepath.Base(path))
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, errors.New("browser relay file exceeds its read budget")
	}
	return raw, nil
}
