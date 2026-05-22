package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/spf13/cobra"

	"github.com/feliux/kscope/internal/bus"
	"github.com/feliux/kscope/internal/collector"
	"github.com/feliux/kscope/internal/correlation"
	correngine "github.com/feliux/kscope/internal/correlation/engine"
	kscopebpf "github.com/feliux/kscope/internal/ebpf"
	"github.com/feliux/kscope/internal/events"
)

type observeConfig struct {
	Output           string
	Modules          string
	BusBuffer        int
	SubscriberBuffer int
	EngineBuffer     int
	DropOnFull       bool
}

func defaultObserveConfig() observeConfig {
	return observeConfig{
		Output:           "human",
		Modules:          "dns,tcp,process",
		BusBuffer:        4096,
		SubscriberBuffer: 1024,
		EngineBuffer:     1024,
		DropOnFull:       false,
	}
}

func addObserveFlags(cmd *cobra.Command, cfg *observeConfig) {
	cmd.Flags().StringVar(&cfg.Output, "output", cfg.Output, "output format: human|json")
	cmd.Flags().StringVar(&cfg.Modules, "modules", cfg.Modules, "modules to enable: dns,tcp,process,all")
	cmd.Flags().IntVar(&cfg.BusBuffer, "bus-buffer", cfg.BusBuffer, "event bus buffer size")
	cmd.Flags().IntVar(&cfg.SubscriberBuffer, "subscriber-buffer", cfg.SubscriberBuffer, "subscriber buffer size")
	cmd.Flags().IntVar(&cfg.EngineBuffer, "engine-buffer", cfg.EngineBuffer, "engine output buffer size")
	cmd.Flags().BoolVar(&cfg.DropOnFull, "drop-on-full", cfg.DropOnFull, "drop events when buffers are full")
}

func runObserve(cfg observeConfig) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stderr, "kscope: ", log.LstdFlags)

	modules, err := parseModules(cfg.Modules)
	if err != nil {
		return err
	}

	manager, err := kscopebpf.LoadAndAttach(kscopebpf.Options{
		EnableDNS:     modules.dns,
		EnableTCP:     modules.tcp,
		EnableProcess: modules.process,
	})
	if err != nil {
		return err
	}
	defer manager.Close()

	reader, err := ringbuf.NewReader(manager.Events())
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	defer reader.Close()

	eventBus := bus.New(bus.Config{
		BufferSize: cfg.BusBuffer,
		DropOnFull: cfg.DropOnFull,
	})
	go eventBus.Run(ctx)

	sub, cancelSub := eventBus.Subscribe("correlation", cfg.SubscriberBuffer)
	defer cancelSub()

	store := correlation.NewStore()
	allowed := allowedEventTypes(modules)
	engine := correngine.New(store, cfg.EngineBuffer, correngine.Options{Allowed: allowed})
	go engine.Run(ctx, sub)

	collector := collector.New(reader, eventBus, logger)
	go func() {
		if err := collector.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("collector stopped: %v", err)
		}
	}()

	writer, err := newSignalWriter(cfg.Output, os.Stdout)
	if err != nil {
		return err
	}

	return writer.Run(ctx, engine.Out())
}

func allowedEventTypes(mods moduleSet) map[events.EventType]bool {
	allowed := make(map[events.EventType]bool)
	if mods.dns {
		allowed[events.EventDNSQuery] = true
		allowed[events.EventDNSReply] = true
	}
	if mods.tcp {
		allowed[events.EventTCPConnect] = true
	}
	if mods.process {
		allowed[events.EventProcessExec] = true
	}
	return allowed
}
