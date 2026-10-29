// socketrail prints, once per interval, which peers this host exchanged TCP
// and UDP traffic with, as JSON Lines.
//
//	socketrail [-cgroup path] [-interval 1m] [-max-entries 65536]
//	socketrail -version
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run(cgroupPath string, interval time.Duration, maxEntries uint32) error {
	t, err := attach(cgroupPath, maxEntries)
	if err != nil {
		return err
	}
	defer t.Close()

	out := json.NewEncoder(os.Stdout)
	tl := newTally(&t.objs, out)

	fmt.Fprintf(os.Stderr, "socketrail %s: watching %s every %s, %d flows per interval\n",
		version, cgroupPath, interval, maxEntries)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-sig:
			// Why not return straight away: the interval in progress would
			// go with it, and stopping the process would be a way to hide
			// traffic.
			return tl.tick()
		case <-tick.C:
		}
		if err := tl.tick(); err != nil {
			return err
		}
	}
}

func main() {
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 path to attach to")
	interval := flag.Duration("interval", time.Minute, "how much traffic each record covers")
	maxEntries := flag.Uint("max-entries", 65536, "distinct flows one interval can hold before counting the rest as dropped")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "socketrail: unexpected argument %q\n", flag.Arg(0))
		flag.Usage()
		os.Exit(2)
	}
	// Why not accept anything shorter: each interval ends with a wait for
	// programs still writing to the map being swapped out, and an interval
	// that is mostly that wait reports little but the wait.
	if *interval < time.Second {
		fmt.Fprintf(os.Stderr, "socketrail: -interval %s is shorter than 1s\n", *interval)
		os.Exit(2)
	}
	// Why not leave the size to the kernel: a value above MaxUint32 would be
	// cut to 32 bits before it got there, and run with a size nobody asked for.
	if *maxEntries > math.MaxUint32 {
		fmt.Fprintf(os.Stderr, "socketrail: -max-entries %d is above %d\n", *maxEntries, uint32(math.MaxUint32))
		os.Exit(2)
	}

	if err := run(*cgroupPath, *interval, uint32(*maxEntries)); err != nil {
		fmt.Fprintf(os.Stderr, "socketrail: %v\n", err)
		os.Exit(1)
	}
}
