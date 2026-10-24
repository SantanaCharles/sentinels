//go:build unix

package config

import (
	"os"
	"syscall"
)

// copyOwner gives path the owner and group of like (e.g. root:sentinels), so
// rewriting a file as root does not lock the service out of it.
func copyOwner(path string, like os.FileInfo) {
	if st, ok := like.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(st.Uid), int(st.Gid))
	}
}
