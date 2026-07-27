// Command global-egress turns a WireGuard configuration bundle into a rotating
// egress proxy for an internal network.
//
// Subcommands:
//
//	import   copy a provider .zip into the catalog directory
//	inspect  summarise a catalog without connecting anywhere
//	probe    measure the real public IP of each slot and store the inventory
//	serve    run the SOCKS5/HTTP proxies and the control API
//	version  print the build version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "import":
		err = runImport(os.Args[2:])
	case "inspect":
		err = runInspect(os.Args[2:])
	case "probe":
		err = runProbe(ctx, os.Args[2:])
	case "serve":
		err = runServe(ctx, os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `global-egress - rotating WireGuard egress proxy

usage:
  global-egress import  -zip <bundle.zip> -dir <catalog-dir>
  global-egress inspect -catalog <dir|zip>
  global-egress probe   -catalog <dir|zip> [-limit N] [-concurrency N] [-country cc]
  global-egress serve   -config <config.yaml>
  global-egress version

Run any subcommand with -h for its flags.
`)
}

// newFlagSet builds a flag set that prints a consistent header on -h.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: global-egress %s [flags]\n\nflags:\n", name)
		fs.PrintDefaults()
	}
	return fs
}
