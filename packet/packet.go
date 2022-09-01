package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	IPv4 = 0x4
	IPv6 = 0x6
)

type Packet []byte

func Ping(srcIP string, dstIP string, seq int) Packet {
	var buf []byte

	buf = append(buf, []byte{
		0x45, 0x00, 0x00, 0x1c,
		0xab, 0xcd, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00,
	}...)
	buf = append(buf, net.ParseIP(srcIP)...)
	buf = append(buf, net.ParseIP(dstIP)...)

	buf = append(buf, []byte{
		0x08, 0x00, 0x00, 0x00,
		0x12, 0x34, 0x00, 0x00,
	}...)

	binary.BigEndian.PutUint16(buf[26:28], uint16(seq))

	sum := 0
	for i := 0; i < 20; i += 2 {
		sum += int(binary.BigEndian.Uint16(buf[i : i+2]))
	}
	sum = sum&0xffff + (sum >> 16)
	sum = 0xffff - sum
	binary.BigEndian.PutUint16(buf[10:12], uint16(sum))

	sum = 0
	for i := 20; i < 28; i += 2 {
		sum += int(binary.BigEndian.Uint16(buf[i : i+2]))
	}
	sum = 0xffff - sum
	binary.BigEndian.PutUint16(buf[22:24], uint16(sum))

	return buf
}

func (p Packet) Version() int {
	return int((p[0] >> 4) & 0xf)
}

func (p Packet) Source() string {
	v := p.Version()
	if v == IPv4 {
		return net.IP(p[12:16]).String()
	} else if v == IPv6 {
		return net.IP(p[8:24]).String()
	}
	return ""
}

func (p Packet) Destination() string {
	v := p.Version()
	if v == IPv4 {
		return net.IP(p[16:20]).String()
	} else if v == IPv6 {
		return net.IP(p[24:40]).String()
	}
	return ""
}

func (p Packet) String() string {
	v := p.Version()
	if v == IPv4 {
		return fmt.Sprintf("IPv4 packet %s -> %s", p.Source(), p.Destination())
	} else if v == IPv6 {
		return fmt.Sprintf("IPv6 packet %s -> %s", p.Source(), p.Destination())
	} else {
		return "invalid packet"
	}
}
