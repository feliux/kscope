package events

import (
	"fmt"
	"sync/atomic"
	"time"
)

type EventType string

const (
	EventDNSQuery   EventType = "dns_query"
	EventDNSReply   EventType = "dns_reply"
	EventTCPConnect EventType = "tcp_connect"
	EventProcessExec EventType = "process_exec"
)

type Event struct {
	ID        string
	Type      EventType
	Timestamp int64

	PID  uint32
	Comm string

	Payload any
}

func NewEvent(eventType EventType, pid uint32, comm string, timestamp int64, payload any) Event {
	return Event{
		ID:        NextID(),
		Type:      eventType,
		Timestamp: timestamp,
		PID:       pid,
		Comm:      comm,
		Payload:   payload,
	}
}

func (e Event) Time() time.Time {
	return time.Unix(0, e.Timestamp)
}

type DNSQuery struct {
	QueryName string
	QueryType string
}

type DNSReply struct {
	QueryName string
	QueryType string
	Answers   []string
	TTL       uint32
}

type TCPConnect struct {
	SrcIP   string
	SrcPort uint16

	DstIP   string
	DstPort uint16

	Success bool
}

type ProcessEvent struct {
	PID     uint32
	PPID    uint32
	Comm    string
	Cmdline string
}

var idCounter atomic.Uint64

func NextID() string {
	return fmt.Sprintf("%d", idCounter.Add(1))
}

func NowTimestamp() int64 {
	return time.Now().UnixNano()
}
