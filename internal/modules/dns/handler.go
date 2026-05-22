package dns

import (
	"github.com/feliux/kscope/internal/correlation"
	"github.com/feliux/kscope/internal/events"
)

func Handle(store *correlation.Store, evt events.Event) *correlation.Signal {
	switch payload := evt.Payload.(type) {
	case events.DNSQuery:
		if payload.QueryName == "" {
			return nil
		}
		return store.AddDNSQuery(
			evt.PID,
			evt.Comm,
			payload.QueryName,
			payload.QueryType,
			evt.Timestamp,
		)
	case events.DNSReply:
		if payload.QueryName == "" {
			return nil
		}
		return store.AddDNSReply(
			evt.PID,
			evt.Comm,
			payload.QueryName,
			payload.QueryType,
			payload.Answers,
			payload.TTL,
			evt.Timestamp,
		)
	default:
		return nil
	}
}
