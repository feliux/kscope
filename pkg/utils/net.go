package utils

import (
	"bytes"
	"net"
)

func IPv4FromUint32(v uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(v)
	ip[1] = byte(v >> 8)
	ip[2] = byte(v >> 16)
	ip[3] = byte(v >> 24)
	return ip
}

func Ntohs(port uint16) uint16 {
	return (port<<8)&0xff00 | port>>8
}

func NullTerminatedString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}
