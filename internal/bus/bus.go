package bus

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/feliux/kscope/internal/events"
)

var ErrDropped = errors.New("event dropped")

type Config struct {
	BufferSize int
	DropOnFull bool
}

type Bus struct {
	cfg Config
	in  chan events.Event

	mu   sync.RWMutex
	subs map[string]*subscriber

	droppedIn atomic.Uint64
}

type subscriber struct {
	name  string
	ch    chan events.Event
	drops atomic.Uint64
}

type Stats struct {
	InDropped        uint64
	InQueueDepth     int
	Subscribers      int
	SubscriberDrops  map[string]uint64
}

func New(cfg Config) *Bus {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}

	return &Bus{
		cfg:  cfg,
		in:   make(chan events.Event, cfg.BufferSize),
		subs: make(map[string]*subscriber),
	}
}

func (b *Bus) Publish(ctx context.Context, evt events.Event) error {
	if b.cfg.DropOnFull {
		select {
		case b.in <- evt:
			return nil
		default:
			b.droppedIn.Add(1)
			return ErrDropped
		}
	}

	select {
	case b.in <- evt:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *Bus) Subscribe(name string, buffer int) (<-chan events.Event, func()) {
	if buffer <= 0 {
		buffer = b.cfg.BufferSize
	}

	sub := &subscriber{
		name: name,
		ch:   make(chan events.Event, buffer),
	}

	b.mu.Lock()
	b.subs[name] = sub
	b.mu.Unlock()

	cancel := func() {
		b.mu.Lock()
		delete(b.subs, name)
		b.mu.Unlock()
	}

	return sub.ch, cancel
}

func (b *Bus) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-b.in:
			b.dispatch(ctx, evt)
		}
	}
}

func (b *Bus) Stats() Stats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	drops := make(map[string]uint64, len(b.subs))
	for name, sub := range b.subs {
		drops[name] = sub.drops.Load()
	}

	return Stats{
		InDropped:       b.droppedIn.Load(),
		InQueueDepth:    len(b.in),
		Subscribers:     len(b.subs),
		SubscriberDrops: drops,
	}
}

func (b *Bus) dispatch(ctx context.Context, evt events.Event) {
	subs := b.snapshotSubscribers()

	for _, sub := range subs {
		if b.cfg.DropOnFull {
			select {
			case sub.ch <- evt:
			default:
				sub.drops.Add(1)
			}
			continue
		}

		select {
		case sub.ch <- evt:
		case <-ctx.Done():
			return
		}
	}
}

func (b *Bus) snapshotSubscribers() []*subscriber {
	b.mu.RLock()
	defer b.mu.RUnlock()

	out := make([]*subscriber, 0, len(b.subs))
	for _, sub := range b.subs {
		out = append(out, sub)
	}

	return out
}
