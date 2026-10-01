// Command wotping pings World of Tanks LoginApp servers using the game's
// own Mercury ping message (LoginInterface ID 2), not ICMP.
//
// Usage:
//
//	wotping [-port 20016] [-count 4] [-timeout 1s] [-interval 1s] host...
//
// Each host is probed `count` times with incrementing sequence numbers
// under one random replyID base; round-trips print ping-style followed
// by a min/avg/max/loss summary per host.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/LockBlock-dev/wot/ping"
)

func main() {
	port := flag.Int("port", ping.DefaultPort, "UDP port of the LoginApp")
	count := flag.Int("count", 4, "pings per host")
	timeout := flag.Duration("timeout", time.Second, "wait per reply")
	interval := flag.Duration("interval", time.Second, "gap between pings")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: wotping [options] host...")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if *count < 1 {
		*count = 1
	}

	client, err := ping.New()
	if err != nil {
		fatal(err)
	}
	defer client.Close()

	failed := false
	for _, host := range flag.Args() {
		if !pingHost(client, host, *port, *count, *timeout, *interval) {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

// pingHost resolves host, runs count exchanges and prints a summary.
// It reports false when nothing came back at all.
func pingHost(client *ping.Client, host string, port, count int, timeout, interval time.Duration) bool {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: resolve: %v\n", host, err)
		return false
	}
	replyID, err := ping.NewReplyID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", host, err)
		return false
	}
	var (
		rtts     []time.Duration
		sent     int
		received int
	)
	for i := 0; i < count; i++ {
		res := client.PingOnce(addr, replyID, uint8(i), timeout)
		sent++
		if res.Err != nil {
			fmt.Printf("no reply from %s seq=%d: %v\n", res.Host, res.Seq, res.Err)
		} else {
			received++
			rtts = append(rtts, res.RTT)
			if res.HasMetric {
				fmt.Printf("reply from %s seq=%d time=%v metric=%04x status=%s\n",
					res.Host, res.Seq, round(res.RTT), res.Metric, res.Status)
			} else {
				fmt.Printf("reply from %s seq=%d time=%v status=%s\n",
					res.Host, res.Seq, round(res.RTT), res.Status)
			}
		}
		if i < count-1 {
			time.Sleep(interval)
		}
	}
	printSummary(addr.String(), sent, received, rtts)
	return received > 0
}

// printSummary prints min/avg/max/loss lines in classic ping style.
func printSummary(host string, sent, received int, rtts []time.Duration) {
	loss := 100.0 * float64(sent-received) / float64(sent)
	fmt.Printf("--- %s ping statistics ---\n", host)
	fmt.Printf("%d sent, %d received, %.0f%% loss\n", sent, received, loss)
	if len(rtts) == 0 {
		return
	}
	min, max, sum := rtts[0], rtts[0], time.Duration(0)
	for _, r := range rtts {
		if r < min {
			min = r
		}
		if r > max {
			max = r
		}
		sum += r
	}
	fmt.Printf("rtt min/avg/max = %v/%v/%v\n",
		round(min), round(sum/time.Duration(len(rtts))), round(max))
}

// round trims sub-microsecond noise for display.
func round(d time.Duration) time.Duration {
	return d.Round(10 * time.Microsecond)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wotping:", err)
	os.Exit(2)
}
