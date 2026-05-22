package redirect

import (
	"context"

	"github.com/feliux/kscope/internal/events"
)

type DNSWatcher struct {
	manager *Manager
}

func NewDNSWatcher(manager *Manager) *DNSWatcher {
	return &DNSWatcher{manager: manager}
}

func (w *DNSWatcher) Run(ctx context.Context, in <-chan events.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-in:
			if !ok {
				return
			}
			if evt.Type != events.EventDNSReply {
				continue
			}
			payload, ok := evt.Payload.(events.DNSReply)
			if !ok {
				continue
			}
			if payload.QueryName == "" || len(payload.Answers) == 0 || payload.TTL == 0 {
				continue
			}
			_ = w.manager.UpdateDomainFromReply(payload.QueryName, payload.Answers, payload.TTL)
		}
	}
}
