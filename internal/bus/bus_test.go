package bus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/feliux/kscope/internal/events"
)

func TestBusDropOnFull(t *testing.T) {
	b := New(Config{
		BufferSize: 1,
		DropOnFull: true,
	})

	ctx := context.Background()
	evt1 := events.NewEvent(events.EventTCPConnect, 1, "proc", events.NowTimestamp(), nil)
	evt2 := events.NewEvent(events.EventTCPConnect, 2, "proc", events.NowTimestamp(), nil)

	if err := b.Publish(ctx, evt1); err != nil {
		t.Fatalf("unexpected error on first publish: %v", err)
	}

	if err := b.Publish(ctx, evt2); !errors.Is(err, ErrDropped) {
		t.Fatalf("expected ErrDropped, got %v", err)
	}
}

func TestBusBackpressure(t *testing.T) {
	b := New(Config{
		BufferSize: 1,
		DropOnFull: false,
	})

	evt1 := events.NewEvent(events.EventTCPConnect, 1, "proc", events.NowTimestamp(), nil)
	evt2 := events.NewEvent(events.EventTCPConnect, 2, "proc", events.NowTimestamp(), nil)

	if err := b.Publish(context.Background(), evt1); err != nil {
		t.Fatalf("unexpected error on first publish: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if err := b.Publish(ctx, evt2); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestBusDispatch(t *testing.T) {
	b := New(Config{
		BufferSize: 4,
		DropOnFull: false,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go b.Run(ctx)

	sub, cancelSub := b.Subscribe("test", 1)
	defer cancelSub()

	evt := events.NewEvent(events.EventProcessExec, 42, "proc", events.NowTimestamp(), events.ProcessEvent{})
	if err := b.Publish(ctx, evt); err != nil {
		t.Fatalf("unexpected publish error: %v", err)
	}

	select {
	case got := <-sub:
		if got.ID != evt.ID {
			t.Fatalf("unexpected event: got %s want %s", got.ID, evt.ID)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}
}
