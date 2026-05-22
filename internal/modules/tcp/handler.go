package tcp

import (
	"github.com/feliux/kscope/internal/correlation"
	"github.com/feliux/kscope/internal/events"
)

func Handle(store *correlation.Store, evt events.Event) *correlation.Signal {
	payload, ok := evt.Payload.(events.TCPConnect)
	if !ok {
		return nil
	}

	if payload.DstIP == "" {
		return nil
	}

	return store.AddTCPConnect(
		evt.PID,
		evt.Comm,
		payload.SrcIP,
		payload.SrcPort,
		payload.DstIP,
		payload.DstPort,
		payload.Success,
		evt.Timestamp,
	)
}
