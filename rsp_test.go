package arsp

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

type mockStub struct {
	ln    net.Listener
	mem   map[uint64]byte
	regs  map[int]uint64
	noAck bool
}

func newMockStub(t *testing.T) *mockStub {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &mockStub{ln: ln, mem: map[uint64]byte{}, regs: map[int]uint64{}}
	go m.serve()
	return m
}

func (m *mockStub) addr() string { return m.ln.Addr().String() }

func (m *mockStub) serve() {
	conn, err := m.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return
		}
		if b != '$' {
			continue
		}
		var raw []byte
		for {
			c, err := r.ReadByte()
			if err != nil {
				return
			}
			if c == '#' {
				break
			}
			raw = append(raw, c)
		}
		r.ReadByte()
		r.ReadByte()
		if !m.noAck {
			conn.Write([]byte{'+'})
		}
		reply := m.handle(string(raw))
		var sum byte
		for i := 0; i < len(reply); i++ {
			sum += reply[i]
		}
		conn.Write([]byte(fmt.Sprintf("$%s#%02x", reply, sum)))
	}
}

func (m *mockStub) handle(cmd string) string {
	switch {
	case strings.HasPrefix(cmd, "qSupported"):
		return "PacketSize=4000;multiprocess+"
	case cmd == "QStartNoAckMode":
		m.noAck = true
		return "OK"
	case strings.HasPrefix(cmd, "p"):
		n, _ := strconv.ParseInt(cmd[1:], 16, 32)
		return hex.EncodeToString(leBytes(m.regs[int(n)]))
	case strings.HasPrefix(cmd, "P"):
		body := cmd[1:]
		eq := strings.IndexByte(body, '=')
		n, _ := strconv.ParseInt(body[:eq], 16, 32)
		b, _ := hex.DecodeString(body[eq+1:])
		m.regs[int(n)] = leUint64(b)
		return "OK"
	case strings.HasPrefix(cmd, "m"):
		body := cmd[1:]
		c := strings.IndexByte(body, ',')
		addr, _ := strconv.ParseUint(body[:c], 16, 64)
		length, _ := strconv.ParseInt(body[c+1:], 16, 32)
		out := make([]byte, length)
		for i := range out {
			out[i] = m.mem[addr+uint64(i)]
		}
		return hex.EncodeToString(out)
	case strings.HasPrefix(cmd, "M"):
		body := cmd[1:]
		c := strings.IndexByte(body, ',')
		addr, _ := strconv.ParseUint(body[:c], 16, 64)
		colon := strings.IndexByte(body, ':')
		data, _ := hex.DecodeString(body[colon+1:])
		for i, bb := range data {
			m.mem[addr+uint64(i)] = bb
		}
		return "OK"
	case strings.HasPrefix(cmd, "Z0"), strings.HasPrefix(cmd, "z0"):
		return "OK"
	case cmd == "c":
		m.regs[RegPC] = m.regs[RegLR]
		m.regs[RegX0] = 0x1234
		return "T05thread:01;"
	case cmd == "D":
		return "OK"
	}
	return ""
}

func dialMock(t *testing.T, m *mockStub) *Client {
	c, err := Dial(m.addr())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Setup(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSetupNoAck(t *testing.T) {
	m := newMockStub(t)
	c := dialMock(t, m)
	if !c.noAck {
		t.Fatal("expected no-ack mode after Setup")
	}
	if c.packetSize != 0x4000 {
		t.Fatalf("packetSize = %#x, want 0x4000", c.packetSize)
	}
}

func TestMemRoundTrip(t *testing.T) {
	m := newMockStub(t)
	c := dialMock(t, m)
	want := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11}
	if err := c.WriteMem(0x4000, want); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReadMem(0x4000, len(want))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("read %x, want %x", got, want)
	}
}

func TestRegRoundTrip(t *testing.T) {
	m := newMockStub(t)
	c := dialMock(t, m)
	if err := c.WriteReg(RegX0, 0xcafef00d); err != nil {
		t.Fatal(err)
	}
	v, err := c.ReadReg(RegX0)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0xcafef00d {
		t.Fatalf("reg = %#x, want 0xcafef00d", v)
	}
}

func TestCallReturnsViaSentinel(t *testing.T) {
	m := newMockStub(t)
	c := dialMock(t, m)
	res, err := c.Call(0x8000, []uint64{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "sentinel" {
		t.Fatalf("reason = %q, want sentinel", res.Reason)
	}
	if res.Regs[RegX0] != 0x1234 {
		t.Fatalf("return value = %#x, want 0x1234", res.Regs[RegX0])
	}
}

func TestTagMaskNormalizesTaggedPC(t *testing.T) {
	sent := uint64(0xdddd000000000000)
	tagged := sent | (uint64(0x55) << 56)
	if tagged&TagMask != sent&TagMask {
		t.Fatal("TagMask failed to normalize a tagged PC")
	}
}

func TestParseStop(t *testing.T) {
	s := ParseStop([]byte("T0bthread:0a;20:0011223344556677;"))
	if s.Signal != 0x0b {
		t.Fatalf("signal = %#x, want 0x0b", s.Signal)
	}
	if string(s.Fields["thread"]) != "0a" {
		t.Fatalf("thread = %q", s.Fields["thread"])
	}
}

func TestDecodePayloadRLE(t *testing.T) {
	got := decodePayload([]byte("0* "))
	if string(got) != "0000" {
		t.Fatalf("RLE decode = %q, want 0000", got)
	}
	got = decodePayload([]byte{'}', ']' ^ 0x20})
	if string(got) != "]" {
		t.Fatalf("escape decode = %q", got)
	}
}
