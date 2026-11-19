package arsp

import "fmt"

const (
	RegX0   = 0
	RegFP   = 29
	RegLR   = 30
	RegSP   = 31
	RegPC   = 32
	RegCPSR = 33
)

const TagMask uint64 = 0x00ffffffffffffff

func (c *Client) GetRegs(nums ...int) (map[int]uint64, error) {
	if len(nums) == 0 {
		for i := 0; i <= RegCPSR; i++ {
			nums = append(nums, i)
		}
	}
	out := make(map[int]uint64, len(nums))
	for _, n := range nums {
		v, err := c.ReadReg(n)
		if err != nil {
			return out, err
		}
		out[n] = v
	}
	return out, nil
}

func (c *Client) SetRegs(regs map[int]uint64) error {
	for n, v := range regs {
		if err := c.WriteReg(n, v); err != nil {
			return err
		}
	}
	return nil
}

type CallResult struct {
	Reason string
	Signal int
	Regs   map[int]uint64
}

type callCfg struct {
	sentinel uint64
	mask     uint64
	bp       uint64
	hasBP    bool
	maxStops int
}

type CallOption func(*callCfg)

func WithSentinel(addr uint64) CallOption { return func(c *callCfg) { c.sentinel = addr } }

func WithMask(m uint64) CallOption { return func(c *callCfg) { c.mask = m } }

func WithBreakpoint(bp uint64) CallOption {
	return func(c *callCfg) { c.bp = bp; c.hasBP = true }
}

func WithMaxStops(n int) CallOption { return func(c *callCfg) { c.maxStops = n } }

func (c *Client) Call(addr uint64, args []uint64, opts ...CallOption) (CallResult, error) {
	cfg := callCfg{sentinel: 0xdddd000000000000, mask: TagMask, maxStops: 12}
	for _, o := range opts {
		o(&cfg)
	}
	if len(args) > 8 {
		return CallResult{}, fmt.Errorf("call: %d args, aarch64 passes at most 8 in registers", len(args))
	}
	for i, a := range args {
		if err := c.WriteReg(RegX0+i, a); err != nil {
			return CallResult{}, err
		}
	}
	if err := c.WriteReg(RegLR, cfg.sentinel); err != nil {
		return CallResult{}, err
	}
	if err := c.WriteReg(RegPC, addr); err != nil {
		return CallResult{}, err
	}

	for i := 0; i < cfg.maxStops; i++ {
		stop, err := c.Continue()
		if err != nil {
			return CallResult{}, err
		}
		regs, err := c.GetRegs(RegX0, RegX0+1, RegX0+2, RegX0+3, RegLR, RegSP, RegPC)
		if err != nil {
			return CallResult{}, err
		}
		pc := regs[RegPC]
		switch {
		case pc&cfg.mask == cfg.sentinel&cfg.mask:
			return CallResult{Reason: "sentinel", Signal: stop.Signal, Regs: regs}, nil
		case cfg.hasBP && pc&cfg.mask == cfg.bp&cfg.mask:
			return CallResult{Reason: "breakpoint", Signal: stop.Signal, Regs: regs}, nil
		case stop.Signal == 5:
			continue
		default:
			return CallResult{Reason: "fault", Signal: stop.Signal, Regs: regs}, nil
		}
	}
	return CallResult{Reason: "maxstops"}, nil
}
