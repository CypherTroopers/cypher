package rewards

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/cypherium/cypher/dex/protocol"
)

const maxCollectorWALBytes = 2 * 1024 * 1024
const collectorMarker = "common-dex-participation-devnet-v1\n"

type collectorWAL struct {
	dir  string
	lock *os.File
}
type collectorEnvelope struct {
	Payload  json.RawMessage
	Checksum protocol.Hash
}

func openCollectorWAL(dir string) (*collectorWAL, error) {
	if err := checkCollectorWALPlatform(); err != nil {
		return nil, err
	}
	if dir == "" {
		return nil, errors.New("collector needs dedicated WAL directory")
	}
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err := os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
		marker, err := collectorOpenNoFollow(filepath.Join(dir, "OWNER"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		if _, err = marker.WriteString(collectorMarker); err == nil {
			err = marker.Sync()
		}
		closeErr := marker.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		for _, path := range []string{dir, filepath.Dir(dir)} {
			d, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			err = d.Sync()
			d.Close()
			if err != nil {
				return nil, err
			}
		}
	} else if err != nil {
		return nil, err
	} else {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("invalid collector WAL directory")
		}
		marker, err := collectorOpenNoFollow(filepath.Join(dir, "OWNER"), os.O_RDONLY, 0)
		if err != nil {
			return nil, errors.New("refuse existing unowned collector WAL directory")
		}
		info, statErr := marker.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			marker.Close()
			return nil, errors.New("invalid collector WAL marker")
		}
		data, readErr := io.ReadAll(io.LimitReader(marker, int64(len(collectorMarker))+1))
		marker.Close()
		if readErr != nil || string(data) != collectorMarker {
			return nil, errors.New("refuse existing unowned collector WAL directory")
		}
	}
	lock, err := collectorOpenNoFollow(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	info, err = lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		lock.Close()
		return nil, errors.New("invalid collector WAL lock")
	}
	if err := collectorLockExclusive(lock); err != nil {
		lock.Close()
		return nil, err
	}
	return &collectorWAL{dir, lock}, nil
}

func (w *collectorWAL) close() error { return w.lock.Close() }
func strictCollectorJSON(data []byte, out interface{}) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing collector WAL data")
	}
	return nil
}
func (w *collectorWAL) load(domain protocol.Domain, registryHash protocol.Hash, index uint8) (collectorDisk, error) {
	var d collectorDisk
	f, err := collectorOpenNoFollow(filepath.Join(w.dir, "state.json"), os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return collectorDisk{Version: 1, Domain: domain, RegistryHash: registryHash, Index: index, Targets: make(map[string][]byte), Issued: make(map[string]Receipt), Certificates: make(map[string][]byte), Closed: make(map[string]protocol.Hash)}, nil
	}
	if err != nil {
		return d, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return d, errors.New("invalid collector WAL state file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCollectorWALBytes+1))
	if err != nil {
		return d, err
	}
	if len(b) > maxCollectorWALBytes {
		return d, errors.New("collector WAL byte bound")
	}
	var e collectorEnvelope
	if err := strictCollectorJSON(b, &e); err != nil {
		return d, err
	}
	if protocol.Digest("common-dex/participation-wal/v1", e.Payload) != e.Checksum {
		return d, errors.New("collector WAL checksum mismatch")
	}
	if err := strictCollectorJSON(e.Payload, &d); err != nil {
		return collectorDisk{}, err
	}
	return d, nil
}

func (w *collectorWAL) save(d collectorDisk) error {
	payload, err := json.Marshal(d)
	if err != nil {
		return err
	}
	data, err := json.Marshal(collectorEnvelope{payload, protocol.Digest("common-dex/participation-wal/v1", payload)})
	if err != nil {
		return err
	}
	if len(data) > maxCollectorWALBytes {
		return errors.New("collector WAL byte bound")
	}
	f, err := os.CreateTemp(w.dir, "state-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(w.dir, "state.json")); err != nil {
		return err
	}
	dir, err := os.Open(w.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
