//go:build !linux

package progress

import "os"

// isTerminalFile uses the portable test: a terminal is a character device,
// and a file or a pipe is not. It cannot tell a terminal from another
// character device such as /dev/null, which is why Linux, where the ioctl is
// available, does not rely on it — but it needs no platform syscall, so it
// builds and behaves sensibly on darwin and windows, where the alternative was
// not building at all.
func isTerminalFile(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
