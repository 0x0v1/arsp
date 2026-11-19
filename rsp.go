package arsp

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	conn       net.Conn
	r          *bufio.Reader
	noAck      bool
	packetSize int
	timeout    time.Duration
}

type Option func(*Client)

func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

func Dial(addr string, opts ...Option) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	c := &Client{conn: conn, r: bufio.NewReader(conn), packetSize: 0x400}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) applyDeadline() {
	if c.timeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	}
}

func decodePayload(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '}':
			if i+1 < len(data) {
				i++
				out = append(out, data[i]^0x20)
			}
		case '*':
			if i+1 < len(data) && len(out) > 0 {
				i++
				n := int(data[i]) - 29
				last := out[len(out)-1]
				for k := 0; k < n; k++ {
					out = append(out, last)
				}
			}
		default:
			out = append(out, data[i])
		}
	}
	return out
}

func escapePayload(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for _, b := range data {
		switch b {
		case '$', '#', '}', '*':
			out = append(out, '}', b^0x20)
		default:
			out = append(out, b)
		}
	}
	return out
}

func (c *Client) recvPacket() ([]byte, error) {
	for {
		c.applyDeadline()
		for {
			b, err := c.r.ReadByte()
			if err != nil {
				return nil, err
			}
			if b == '$' {
				break
			}
		}
		var raw []byte
		for {
			b, err := c.r.ReadByte()
			if err != nil {
				return nil, err
			}
			if b == '#' {
				break
			}
			raw = append(raw, b)
		}
		hi, err := c.r.ReadByte()
		if err != nil {
			return nil, err
		}
		lo, err := c.r.ReadByte()
		if err != nil {
			return nil, err
		}
		if c.noAck {
			return decodePayload(raw), nil
		}
		var sum byte
		for _, x := range raw {
			sum += x
		}
		want, perr := strconv.ParseUint(string([]byte{hi, lo}), 16, 8)
		if perr == nil && sum == byte(want) {
			if _, err := c.conn.Write([]byte{'+'}); err != nil {
				return nil, err
			}
			return decodePayload(raw), nil
		}
		if _, err := c.conn.Write([]byte{'-'}); err != nil {
			return nil, err
		}
	}
}

func (c *Client) sendPacket(data []byte) error {
	esc := escapePayload(data)
	var sum byte
	for _, x := range esc {
		sum += x
	}
	pkt := append([]byte{'$'}, esc...)
	pkt = append(pkt, '#')
	pkt = append(pkt, []byte(fmt.Sprintf("%02x", sum))...)
	for {
		if _, err := c.conn.Write(pkt); err != nil {
			return err
		}
		if c.noAck {
			return nil
		}
		c.applyDeadline()
		for {
			b, err := c.r.ReadByte()
			if err != nil {
				return err
			}
			if b == '+' {
				return nil
			}
			if b == '-' {
				break
			}
		}
	}
}

func (c *Client) Cmd(data string) ([]byte, error) {
	if err := c.sendPacket([]byte(data)); err != nil {
		return nil, err
	}
	return c.recvPacket()
}

func (c *Client) Setup() (string, error) {
	r, err := c.Cmd("qSupported:xmlRegisters=aarch64;multiprocess+")
	if err != nil {
		return "", err
	}
	for _, tok := range strings.Split(string(r), ";") {
		if strings.HasPrefix(tok, "PacketSize=") {
			if v, e := strconv.ParseInt(tok[len("PacketSize="):], 16, 64); e == nil && v > 0 {
				c.packetSize = int(v)
			}
		}
	}
	if ok, _ := c.Cmd("QStartNoAckMode"); string(ok) == "OK" {
		c.noAck = true
	}
	return string(r), nil
}

func (c *Client) ReadMem(addr uint64, length int) ([]byte, error) {
	out := make([]byte, 0, length)
	chunk := (c.packetSize - 16) / 2
	if chunk < 0x100 {
		chunk = 0x100
	}
	for off := 0; off < length; {
		n := length - off
		if n > chunk {
			n = chunk
		}
		r, err := c.Cmd(fmt.Sprintf("m%x,%x", addr+uint64(off), n))
		if err != nil {
			return nil, err
		}
		if len(r) > 0 && r[0] == 'E' {
			return nil, fmt.Errorf("read_mem E@%#x: %s", addr+uint64(off), r)
		}
		b, err := hexDecode(r)
		if err != nil {
			return nil, fmt.Errorf("read_mem decode @%#x: %w", addr+uint64(off), err)
		}
		out = append(out, b...)
		off += n
	}
	return out, nil
}

func (c *Client) WriteMem(addr uint64, data []byte) error {
	chunk := (c.packetSize - 32) / 2
	if chunk < 0x80 {
		chunk = 0x80
	}
	for off := 0; off < len(data); {
		n := len(data) - off
		if n > chunk {
			n = chunk
		}
		seg := data[off : off+n]
		r, err := c.Cmd(fmt.Sprintf("M%x,%x:%s", addr+uint64(off), n, hexEncode(seg)))
		if err != nil {
			return err
		}
		if string(r) != "OK" {
			return fmt.Errorf("write_mem E@%#x: %s", addr+uint64(off), r)
		}
		off += n
	}
	return nil
}

func (c *Client) ReadReg(n int) (uint64, error) {
	r, err := c.Cmd(fmt.Sprintf("p%x", n))
	if err != nil {
		return 0, err
	}
	if len(r) == 0 || r[0] == 'E' {
		return 0, fmt.Errorf("read_reg %d: %s", n, r)
	}
	b, err := hexDecode(r)
	if err != nil {
		return 0, fmt.Errorf("read_reg %d decode: %w", n, err)
	}
	return leUint64(b), nil
}

func (c *Client) WriteReg(n int, val uint64) error {
	r, err := c.Cmd(fmt.Sprintf("P%x=%s", n, hexEncode(leBytes(val))))
	if err != nil {
		return err
	}
	if string(r) != "OK" {
		return fmt.Errorf("write_reg %d: %s", n, r)
	}
	return nil
}

func (c *Client) SetBreakpoint(addr uint64) error {
	r, err := c.Cmd(fmt.Sprintf("Z0,%x,4", addr))
	if err != nil {
		return err
	}
	if string(r) != "OK" {
		return fmt.Errorf("set_bp %#x: %s", addr, r)
	}
	return nil
}

func (c *Client) ClearBreakpoint(addr uint64) error {
	r, err := c.Cmd(fmt.Sprintf("z0,%x,4", addr))
	if err != nil {
		return err
	}
	if string(r) != "OK" {
		return fmt.Errorf("clear_bp %#x: %s", addr, r)
	}
	return nil
}

func (c *Client) Continue() (Stop, error) {
	r, err := c.Cmd("c")
	if err != nil {
		return Stop{}, err
	}
	return ParseStop(r), nil
}

func (c *Client) Step() (Stop, error) {
	r, err := c.Cmd("s")
	if err != nil {
		return Stop{}, err
	}
	return ParseStop(r), nil
}

func (c *Client) Detach() error {
	_, err := c.Cmd("D")
	return err
}

type Stop struct {
	Signal int
	Fields map[string][]byte
	Raw    []byte
}

func ParseStop(pkt []byte) Stop {
	s := Stop{Fields: map[string][]byte{}, Raw: pkt}
	if len(pkt) < 3 || (pkt[0] != 'T' && pkt[0] != 'S') {
		return s
	}
	if v, err := strconv.ParseInt(string(pkt[1:3]), 16, 32); err == nil {
		s.Signal = int(v)
	}
	if pkt[0] == 'T' {
		for _, kv := range strings.Split(string(pkt[3:]), ";") {
			if kv == "" || !strings.Contains(kv, ":") {
				continue
			}
			parts := strings.SplitN(kv, ":", 2)
			s.Fields[parts[0]] = []byte(parts[1])
		}
	}
	return s
}
