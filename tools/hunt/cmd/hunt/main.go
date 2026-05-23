// hunt — run detection-as-code queries against a Loki backend.
//
//   hunt list                       # show every defined hunt
//   hunt run                        # run every hunt over the last 1h, exit 1 if any fires
//   hunt run --since 24h            # custom lookback
//   hunt run --id HUNT-001          # one hunt
//   hunt run --format json          # for SIEMs / dashboards
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mohidev-tech/runtime-detect/tools/hunt/internal/hunts"
	"github.com/mohidev-tech/runtime-detect/tools/hunt/internal/loki"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "list":
		cmdList()
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`hunt — detection-as-code over a Loki backend

Usage:
  hunt list                    Show every defined hunt
  hunt run [flags]             Run hunts and report

run flags:
  --loki URL          Loki HTTP base URL (default http://localhost:3100, or $LOKI_URL)
  --since DURATION    Lookback (default 1h)
  --id ID             Run only the hunt with this ID
  --format FMT        console (default) or json
  --fail-on-hit       Exit 1 if any hunt fires (default true)
`)
}

func cmdList() {
	for _, h := range hunts.All() {
		fmt.Printf("%s  %s\n", h.ID, h.Title)
		fmt.Printf("    tags: %v\n", h.Tags)
		fmt.Printf("    %s\n\n", strings.TrimSpace(h.Description))
	}
}

type result struct {
	Hunt  hunts.Hunt    `json:"hunt"`
	Hits  int           `json:"hits"`
	Fired bool          `json:"fired"`
	First *time.Time    `json:"first_seen,omitempty"`
	Last  *time.Time    `json:"last_seen,omitempty"`
	Sample []loki.Sample `json:"sample,omitempty"`
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	lokiURL := fs.String("loki", envOr("LOKI_URL", "http://localhost:3100"), "")
	since := fs.Duration("since", time.Hour, "")
	id := fs.String("id", "", "")
	format := fs.String("format", "console", "")
	failOnHit := fs.Bool("fail-on-hit", true, "")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := loki.New(*lokiURL)
	end := time.Now()
	start := end.Add(-*since)

	var results []result
	anyFired := false

	for _, h := range hunts.All() {
		if *id != "" && h.ID != *id {
			continue
		}
		samples, err := c.QueryRange(ctx, h.LogQL, start, end, 1000)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] query error: %v\n", h.ID, err)
			results = append(results, result{Hunt: h})
			continue
		}
		r := result{Hunt: h, Hits: len(samples)}
		if r.Hits >= h.MinHits {
			r.Fired = true
			anyFired = true
		}
		if len(samples) > 0 {
			first := samples[0].Time
			last := samples[len(samples)-1].Time
			r.First = &first
			r.Last = &last
			// Keep at most 3 sample lines in the output — enough to see what's
			// happening without flooding the terminal.
			n := len(samples)
			if n > 3 {
				n = 3
			}
			r.Sample = samples[:n]
		}
		results = append(results, r)
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	default:
		printConsole(results, start, end)
	}

	if anyFired && *failOnHit {
		return 1
	}
	return 0
}

func printConsole(rs []result, start, end time.Time) {
	fmt.Printf("hunts run over [%s, %s]\n\n", start.Format(time.RFC3339), end.Format(time.RFC3339))
	fired, total := 0, len(rs)
	for _, r := range rs {
		if r.Fired {
			fired++
			fmt.Printf("FIRED  %s  %s  (hits=%d)\n", r.Hunt.ID, r.Hunt.Title, r.Hits)
			if r.First != nil {
				fmt.Printf("       first: %s   last: %s\n", r.First.Format(time.RFC3339), r.Last.Format(time.RFC3339))
			}
			for _, s := range r.Sample {
				line := s.Line
				if len(line) > 200 {
					line = line[:200] + "…"
				}
				fmt.Printf("       > %s\n", line)
			}
			fmt.Println()
		} else {
			fmt.Printf("clean  %s  %s\n", r.Hunt.ID, r.Hunt.Title)
		}
	}
	fmt.Printf("\nsummary: %d/%d hunts fired\n", fired, total)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
