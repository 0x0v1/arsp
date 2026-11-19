package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/0x0v1/arsp"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:1234", "lldb-server gdbserver address")

	switch cmd {
	case "regs":
		fs.Parse(os.Args[2:])
		withClient(*addr, func(c *arsp.Client) error {
			regs, err := c.GetRegs()
			if err != nil {
				return err
			}
			for i := 0; i <= 30; i++ {
				fmt.Printf("x%-2d = %#018x\n", i, regs[i])
			}
			fmt.Printf("sp  = %#018x\npc  = %#018x\ncpsr= %#018x\n",
				regs[arsp.RegSP], regs[arsp.RegPC], regs[arsp.RegCPSR])
			return nil
		})
	case "readmem":
		at := fs.String("at", "", "address, hex (0x...) or decimal")
		n := fs.Int("n", 64, "byte count")
		fs.Parse(os.Args[2:])
		withClient(*addr, func(c *arsp.Client) error {
			b, err := c.ReadMem(parseU64(*at), *n)
			if err != nil {
				return err
			}
			fmt.Print(hex.Dump(b))
			return nil
		})
	case "call":
		pc := fs.String("pc", "", "function address to call")
		argsStr := fs.String("args", "", "comma-separated x0.. values")
		bp := fs.String("bp", "", "optional breakpoint address treated as success")
		fs.Parse(os.Args[2:])
		withClient(*addr, func(c *arsp.Client) error {
			var args []uint64
			if *argsStr != "" {
				for _, s := range strings.Split(*argsStr, ",") {
					args = append(args, parseU64(strings.TrimSpace(s)))
				}
			}
			saved, err := c.GetRegs()
			if err != nil {
				return err
			}
			var opts []arsp.CallOption
			if *bp != "" {
				bpAddr := parseU64(*bp)
				if err := c.SetBreakpoint(bpAddr); err != nil {
					return err
				}
				opts = append(opts, arsp.WithBreakpoint(bpAddr))
			}
			res, err := c.Call(parseU64(*pc), args, opts...)
			if err != nil {
				return err
			}
			fmt.Printf("reason=%s signal=%d x0=%#x\n", res.Reason, res.Signal, res.Regs[arsp.RegX0])
			return c.SetRegs(saved)
		})
	default:
		usage()
	}
}

func withClient(addr string, fn func(*arsp.Client) error) {
	c, err := arsp.Dial(addr)
	if err != nil {
		die(err)
	}
	defer c.Close()
	if _, err := c.Setup(); err != nil {
		die(err)
	}
	if err := fn(c); err != nil {
		die(err)
	}
}

func parseU64(s string) uint64 {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		base = 16
	}
	v, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		die(fmt.Errorf("bad number %q: %w", s, err))
	}
	return v
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "arsp:", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  arsp regs    -addr HOST:PORT
  arsp readmem -addr HOST:PORT -at ADDR -n N
  arsp call    -addr HOST:PORT -pc ADDR [-args a,b,c] [-bp ADDR]`)
	os.Exit(2)
}
