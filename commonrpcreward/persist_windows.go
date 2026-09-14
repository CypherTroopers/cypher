package commonrpcreward

import "golang.org/x/sys/windows"

func renameFile(from, to string) error {
	source, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	// MoveFileEx with WRITE_THROUGH completes the name update before returning.
	return windows.MoveFileEx(source, target, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// Windows does not support FlushFileBuffers on directory handles. The file is
// flushed before the write-through rename above; the datadir's ACL protects it.
func syncDirectory(string) error { return nil }
