package arsp

import "encoding/hex"

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

func hexDecode(b []byte) ([]byte, error) { return hex.DecodeString(string(b)) }

func leUint64(b []byte) uint64 {
	var v uint64
	for i := 0; i < len(b) && i < 8; i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

func leBytes(v uint64) []byte {
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return b
}
