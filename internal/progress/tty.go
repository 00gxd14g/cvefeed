package progress

import "os"

// isTerminal reports whether f is a terminal, which decides whether anything is
// drawn at all. Writing escape codes into a redirected file or a pipe would
// corrupt whatever is reading it.
//
// CVEFEED_NO_PROGRESS forces it off, for the CI logs and cron jobs that do
// allocate a terminal and still want none of this.
//
// The actual check is per platform: Linux asks the kernel with the termios
// ioctl (tty_linux.go); everywhere else uses the character-device test, which
// the standard library can answer without a syscall the platform may not have
// (tty_other.go). The package used to have only the ioctl, without a build
// constraint, and did not compile on darwin or windows at all.
func isTerminal(f *os.File) bool {
	if os.Getenv("CVEFEED_NO_PROGRESS") != "" {
		return false
	}
	if f == nil {
		return false
	}
	return isTerminalFile(f)
}
