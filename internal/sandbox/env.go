package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
)

// SocketPath returns the path for the daemon's Unix Domain Socket.
func SocketPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("enclave-unboxexec-%d.sock", os.Getpid()))
}

// ProfilePath returns the path for the evaluated sandbox profile file.
func ProfilePath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("enclave-profile-%d.sb", os.Getpid()))
}

// ConfigDumpPath returns the path for the effective config dump file.
func ConfigDumpPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("enclave-config-%d.toml", os.Getpid()))
}
