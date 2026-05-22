package engine

import (
	"context"

	"github.com/feliux/kscope/internal/correlation"
	"github.com/feliux/kscope/internal/events"
	"github.com/feliux/kscope/internal/modules/dns"
	"github.com/feliux/kscope/internal/modules/process"
	"github.com/feliux/kscope/internal/modules/tcp"
)

type Options struct {
	Allowed map[events.EventType]bool
}

type Engine struct {
	store   *correlation.Store
	out     chan correlation.Signal
	allowed map[events.EventType]bool
}

func New(store *correlation.Store, buffer int, opts Options) *Engine {
	if buffer <= 0 {
		buffer = 1024
	}

	var allowed map[events.EventType]bool
	if len(opts.Allowed) > 0 {
		allowed = opts.Allowed
	}

	return &Engine{
		store:   store,
		out:     make(chan correlation.Signal, buffer),
		allowed: allowed,
	}
}

func (e *Engine) Out() <-chan correlation.Signal {
	return e.out
}

func (e *Engine) Run(ctx context.Context, in <-chan events.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-in:
			if !ok {
				return
			}

			var sig *correlation.Signal

			if e.allowed != nil && !e.allowed[evt.Type] {
				continue
			}

			switch evt.Type {
			case events.EventDNSQuery, events.EventDNSReply:
				sig = dns.Handle(e.store, evt)
			case events.EventTCPConnect:
				sig = tcp.Handle(e.store, evt)
			case events.EventProcessExec:
				sig = process.Handle(e.store, evt)
			default:
				continue
			}

			if sig == nil {
				continue
			}

			select {
			case e.out <- *sig:
			case <-ctx.Done():
				return
			}
		}
	}
}
