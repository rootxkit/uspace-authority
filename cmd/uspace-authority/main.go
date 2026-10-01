// Command uspace-authority is the image entrypoint: the first argument
// names the process to run (one of the seven, each built as its own
// binary and executed in place of this one) or the one-shot migrate
// subcommand, which applies both migration trees and exits.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := dispatch(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}
