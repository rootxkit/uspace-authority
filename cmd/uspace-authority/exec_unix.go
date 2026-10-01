//go:build unix

package main

import (
	"io"
	"os"
	"syscall"

	"github.com/rootxkit/uspace-authority/internal/proc"
)

// execProcess replaces this process with the named binary, so the
// process receives SIGTERM directly and its exit code is the
// container's.
func execProcess(name string, args []string, stderr io.Writer) int {
	path, err := processPath(name)
	if err == nil {
		err = syscall.Exec(path, append([]string{name}, args...), os.Environ()) //nolint:gosec // the path is one of seven fixed names under the image's libexec directory
	}
	_, _ = io.WriteString(stderr, "cannot start "+name+": "+err.Error()+"\n")
	return proc.ExitFailed
}
