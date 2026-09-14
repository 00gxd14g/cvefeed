//go:build linux

package progress

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminalFile asks the kernel: TCGETS succeeds only on a terminal. This is
// the same test isatty(3) makes.
func isTerminalFile(f *os.File) bool {
	var termios [64]byte
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios[0])), 0, 0, 0)
	return err == 0
}
