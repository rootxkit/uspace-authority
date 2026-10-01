//go:build !unix

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"

	"github.com/rootxkit/uspace-authority/internal/proc"
)

// execProcess runs the named binary as a child (no exec(2) here) with
// the same standard streams and returns its exit code. Development only;
// the image is Linux.
func execProcess(name string, args []string, stderr io.Writer) int {
	path, err := processPath(name)
	if err != nil {
		_, _ = io.WriteString(stderr, "cannot start "+name+": "+err.Error()+"\n")
		return proc.ExitFailed
	}
	cmd := exec.Command(path+".exe", args...) //nolint:gosec // one of seven fixed names beside this executable
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		_, _ = io.WriteString(stderr, "cannot start "+name+": "+err.Error()+"\n")
		return proc.ExitFailed
	}
	return proc.ExitOK
}
