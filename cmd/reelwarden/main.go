// Command reelwarden finds duplicate and visually similar videos, explains
// which copy is worth keeping, and writes read-only plans.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hidetzu/reelwarden/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fi, _ := os.Stderr.Stat()
	tty := fi != nil && fi.Mode()&os.ModeCharDevice != 0
	code := cli.Run(ctx, os.Args[1:], cli.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, ErrTTY: tty})
	stop()
	os.Exit(code)
}
