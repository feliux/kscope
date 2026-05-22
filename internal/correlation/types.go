package correlation

type SignalKind string

const (
	SignalDNS     SignalKind = "dns"
	SignalTCP     SignalKind = "tcp"
	SignalProcess SignalKind = "process"
)

type Signal struct {
	Kind      SignalKind `json:"kind"`
	Timestamp int64      `json:"timestamp"`
	PID       uint32     `json:"pid"`
	PPID      uint32     `json:"ppid,omitempty"`
	Comm      string     `json:"comm,omitempty"`
	Cmdline   string     `json:"cmdline,omitempty"`

	Domain    string   `json:"domain,omitempty"`
	QueryType string   `json:"query_type,omitempty"`
	Response  bool     `json:"response,omitempty"`
	Answers   []string `json:"answers,omitempty"`

	IP      string `json:"ip,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Success bool   `json:"success,omitempty"`
}

type ProcessContext struct {
	PID     uint32
	PPID    uint32
	Comm    string
	Cmdline string

	DNS        map[string][]string
	IPToDomain map[string]string

	Connections []TCPConn
}

type TCPConn struct {
	SrcIP   string
	SrcPort uint16

	DstIP   string
	DstPort uint16

	Domain    string
	Success   bool
	Timestamp int64
}
