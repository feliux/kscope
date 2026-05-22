package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/feliux/kscope/internal/bus"
	"github.com/feliux/kscope/internal/events"
	"github.com/feliux/kscope/pkg/utils"
)

const (
	bpfEventTCPConnect  uint32 = 1
	bpfEventDNSQuery    uint32 = 2
	bpfEventDNSReply    uint32 = 3
	bpfEventProcessExec uint32 = 4

	bpfEventHeaderSize = 32
)

type Collector struct {
	reader *ringbuf.Reader
	bus    *bus.Bus
	logger *log.Logger
}

func New(reader *ringbuf.Reader, bus *bus.Bus, logger *log.Logger) *Collector {
	if logger == nil {
		logger = log.New(os.Stderr, "collector: ", log.LstdFlags)
	}

	return &Collector{
		reader: reader,
		bus:    bus,
		logger: logger,
	}
}

func (c *Collector) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		c.reader.Close()
	}()

	for {
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) {
				return nil
			}
			c.logger.Printf("ringbuf read error: %v", err)
			continue
		}

		evt, err := decodeEvent(record.RawSample)
		if err != nil {
			c.logger.Printf("decode error: %v", err)
			continue
		}

		if err := c.bus.Publish(ctx, evt); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			if errors.Is(err, bus.ErrDropped) {
				continue
			}
			c.logger.Printf("publish error: %v", err)
		}
	}
}

type bpfEvent struct {
	Type      uint32
	PID       uint32
	Timestamp uint64
	Comm      [16]byte
	Data      bpfDNSEvent
}

type bpfTCPEvent struct {
	IPVersion uint8
	Success   uint8
	SPort     uint16
	DPort     uint16
	Pad       uint16
	SAddrV4   uint32
	DAddrV4   uint32
	SAddrV6   [16]byte
	DAddrV6   [16]byte
}

type bpfDNSEvent struct {
	PayloadLen uint32
	Payload    [256]byte
}

type bpfProcessEvent struct {
	PPID uint32
}

func decodeEvent(data []byte) (events.Event, error) {
	if len(data) < bpfEventHeaderSize {
		return events.Event{}, fmt.Errorf("short bpf event: %d bytes", len(data))
	}

	var raw bpfEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return events.Event{}, fmt.Errorf("decode bpf event: %w", err)
	}

	comm := utils.NullTerminatedString(raw.Comm[:])
	ts := int64(raw.Timestamp)

	switch raw.Type {
	case bpfEventTCPConnect:
		tcp, err := decodeTCP(data)
		if err != nil {
			return events.Event{}, err
		}
		srcIP := ""
		dstIP := ""
		if tcp.IPVersion == 6 {
			srcIP = net.IP(tcp.SAddrV6[:]).String()
			dstIP = net.IP(tcp.DAddrV6[:]).String()
		} else {
			srcIP = utils.IPv4FromUint32(tcp.SAddrV4).String()
			dstIP = utils.IPv4FromUint32(tcp.DAddrV4).String()
		}

		payload := events.TCPConnect{
			SrcIP:   srcIP,
			SrcPort: tcp.SPort,
			DstIP:   dstIP,
			DstPort: utils.Ntohs(tcp.DPort),
			Success: tcp.Success == 1,
		}
		return events.NewEvent(events.EventTCPConnect, raw.PID, comm, ts, payload), nil
	case bpfEventDNSQuery:
		payloadBytes, err := decodeDNS(data)
		if err != nil {
			return events.Event{}, err
		}
		name, qtype, _, _, ok := parseDNS(payloadBytes)
		payload := events.DNSQuery{}
		if ok {
			payload.QueryName = name
			payload.QueryType = dnsTypeToString(qtype)
		}
		return events.NewEvent(events.EventDNSQuery, raw.PID, comm, ts, payload), nil
	case bpfEventDNSReply:
		payloadBytes, err := decodeDNS(data)
		if err != nil {
			return events.Event{}, err
		}
		name, qtype, answers, minTTL, ok := parseDNS(payloadBytes)
		payload := events.DNSReply{}
		if ok {
			payload.QueryName = name
			payload.QueryType = dnsTypeToString(qtype)
			payload.Answers = answers
			payload.TTL = minTTL
		}
		return events.NewEvent(events.EventDNSReply, raw.PID, comm, ts, payload), nil
	case bpfEventProcessExec:
		proc, err := decodeProcess(data)
		if err != nil {
			return events.Event{}, err
		}
		payload := events.ProcessEvent{
			PID:  raw.PID,
			PPID: proc.PPID,
			Comm: comm,
		}
		return events.NewEvent(events.EventProcessExec, raw.PID, comm, ts, payload), nil
	default:
		return events.Event{}, fmt.Errorf("unknown event type: %d", raw.Type)
	}
}

func decodeTCP(data []byte) (bpfTCPEvent, error) {
	var tcp bpfTCPEvent
	if err := binary.Read(bytes.NewReader(data[bpfEventHeaderSize:]), binary.LittleEndian, &tcp); err != nil {
		return bpfTCPEvent{}, fmt.Errorf("decode tcp: %w", err)
	}
	return tcp, nil
}

func decodeDNS(data []byte) ([]byte, error) {
	var dns bpfDNSEvent
	if err := binary.Read(bytes.NewReader(data[bpfEventHeaderSize:]), binary.LittleEndian, &dns); err != nil {
		return nil, fmt.Errorf("decode dns: %w", err)
	}

	length := int(dns.PayloadLen)
	if length > len(dns.Payload) {
		length = len(dns.Payload)
	}
	if length < 0 {
		length = 0
	}

	return dns.Payload[:length], nil
}

func decodeProcess(data []byte) (bpfProcessEvent, error) {
	var proc bpfProcessEvent
	if err := binary.Read(bytes.NewReader(data[bpfEventHeaderSize:]), binary.LittleEndian, &proc); err != nil {
		return bpfProcessEvent{}, fmt.Errorf("decode process: %w", err)
	}
	return proc, nil
}

func parseDNS(payload []byte) (string, uint16, []string, uint32, bool) {
	if len(payload) < 12 {
		return "", 0, nil, 0, false
	}

	qdcount := binary.BigEndian.Uint16(payload[4:6])
	ancount := binary.BigEndian.Uint16(payload[6:8])
	if qdcount == 0 {
		return "", 0, nil, 0, false
	}

	offset := 12
	name, offset, ok := readDNSName(payload, offset)
	if !ok || offset+4 > len(payload) {
		return "", 0, nil, 0, false
	}

	qtype := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 4

	answers := make([]string, 0, ancount)
	var minTTL uint32
	hasTTL := false

	for i := 0; i < int(ancount); i++ {
		_, offset, ok = readDNSName(payload, offset)
		if !ok || offset+10 > len(payload) {
			break
		}

		rtype := binary.BigEndian.Uint16(payload[offset : offset+2])
		ttl := binary.BigEndian.Uint32(payload[offset+4 : offset+8])
		rdlen := binary.BigEndian.Uint16(payload[offset+8 : offset+10])
		offset += 10

		if offset+int(rdlen) > len(payload) {
			break
		}

		if rtype == 1 && rdlen == 4 {
			answers = append(answers, net.IP(payload[offset:offset+4]).String())
			if !hasTTL || ttl < minTTL {
				minTTL = ttl
				hasTTL = true
			}
		} else if rtype == 28 && rdlen == 16 {
			answers = append(answers, net.IP(payload[offset:offset+16]).String())
			if !hasTTL || ttl < minTTL {
				minTTL = ttl
				hasTTL = true
			}
		}

		offset += int(rdlen)
	}

	return name, qtype, answers, minTTL, true
}

func readDNSName(msg []byte, off int) (string, int, bool) {
	if off >= len(msg) {
		return "", 0, false
	}

	labels := make([]string, 0, 4)
	i := off
	next := off
	jumped := false

	for steps := 0; steps < 128; steps++ {
		if i >= len(msg) {
			return "", 0, false
		}

		l := msg[i]

		if l&0xC0 == 0xC0 {
			if i+1 >= len(msg) {
				return "", 0, false
			}
			ptr := int(l&0x3F)<<8 | int(msg[i+1])
			if ptr >= len(msg) {
				return "", 0, false
			}
			if !jumped {
				next = i + 2
				jumped = true
			}
			i = ptr
			continue
		}

		if l == 0 {
			if !jumped {
				next = i + 1
			}
			return strings.Join(labels, "."), next, true
		}

		if l > 63 || i+1+int(l) > len(msg) {
			return "", 0, false
		}

		labels = append(labels, string(msg[i+1:i+1+int(l)]))
		i += 1 + int(l)
		if !jumped {
			next = i
		}
	}

	return "", 0, false
}

func dnsTypeToString(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 2:
		return "NS"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}
