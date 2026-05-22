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
	kscopebpf "github.com/feliux/kscope/internal/ebpf"
	"github.com/feliux/kscope/internal/proxy"
	"github.com/feliux/kscope/internal/redirect"
)

type proxyConfig struct {
	ConfigPath string
	CgroupPath string

	ListenV4   string
	ListenV6   string
	RedirectV4 string
	RedirectV6 string

	RulePIDs    []string
	RuleComms   []string
	RuleIPs     []string
	RuleDomains []string

	BusBuffer        int
	SubscriberBuffer int
	DropOnFull       bool
}

func defaultProxyConfig() proxyConfig {
	return proxyConfig{
		ConfigPath:       "configs/kscope-rules.yaml",
		ListenV4:         redirect.DefaultListenV4,
		ListenV6:         "",
		RedirectV4:       redirect.DefaultRedirectV4,
		RedirectV6:       "",
		BusBuffer:        1024,
		SubscriberBuffer: 512,
		DropOnFull:       true,
	}
}

func addProxyFlags(cmd *cobra.Command, cfg *proxyConfig) {
	cmd.Flags().StringVar(&cfg.ConfigPath, "config", cfg.ConfigPath, "path to rules config (YAML)")
	cmd.Flags().StringVar(&cfg.CgroupPath, "cgroup", cfg.CgroupPath, "cgroup v2 path (default: /sys/fs/cgroup)")
	cmd.Flags().StringVar(&cfg.ListenV4, "proxy-listen-v4", cfg.ListenV4, "proxy listen address (IPv4)")
	cmd.Flags().StringVar(&cfg.ListenV6, "proxy-listen-v6", cfg.ListenV6, "proxy listen address (IPv6)")
	cmd.Flags().StringVar(&cfg.RedirectV4, "proxy-redirect-v4", cfg.RedirectV4, "redirect target (IPv4)")
	cmd.Flags().StringVar(&cfg.RedirectV6, "proxy-redirect-v6", cfg.RedirectV6, "redirect target (IPv6)")

	cmd.Flags().StringSliceVar(&cfg.RulePIDs, "rule-pid", cfg.RulePIDs, "pid rules for redirection")
	cmd.Flags().StringSliceVar(&cfg.RuleComms, "rule-comm", cfg.RuleComms, "comm rules for redirection")
	cmd.Flags().StringSliceVar(&cfg.RuleIPs, "rule-ip", cfg.RuleIPs, "ip rules for redirection (ip or ip:port)")
	cmd.Flags().StringSliceVar(&cfg.RuleDomains, "rule-domain", cfg.RuleDomains, "domain rules for redirection (domain or domain:port)")

	cmd.Flags().IntVar(&cfg.BusBuffer, "bus-buffer", cfg.BusBuffer, "dns watcher bus buffer size")
	cmd.Flags().IntVar(&cfg.SubscriberBuffer, "subscriber-buffer", cfg.SubscriberBuffer, "dns watcher subscriber buffer size")
	cmd.Flags().BoolVar(&cfg.DropOnFull, "drop-on-full", cfg.DropOnFull, "drop dns events when buffers are full")
}

func runProxy(cfg proxyConfig) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stderr, "kscope-proxy: ", log.LstdFlags)

	pids, err := parsePIDList(cfg.RulePIDs)
	if err != nil {
		return err
	}

	cliCfg := redirect.Config{
		Proxy: redirect.ProxyConfig{
			ListenV4:   cfg.ListenV4,
			ListenV6:   cfg.ListenV6,
			RedirectV4: cfg.RedirectV4,
			RedirectV6: cfg.RedirectV6,
		},
		Rules: redirect.RulesConfig{
			PIDs:    pids,
			Comms:   cfg.RuleComms,
			IPs:     cfg.RuleIPs,
			Domains: cfg.RuleDomains,
		},
	}

	fileCfg, err := redirect.LoadConfig(cfg.ConfigPath)
	loadedFile := err == nil
	if err != nil && !errors.Is(err, redirect.ErrConfigNotFound) {
		return err
	}

	merged := cliCfg
	if loadedFile {
		merged = redirect.MergeConfig(cliCfg, fileCfg)
	}
	merged = redirect.WithDefaults(merged)

	manager, err := kscopebpf.LoadAndAttach(kscopebpf.Options{
		EnableDNS:      len(merged.Rules.Domains) > 0,
		EnableRedirect: true,
		CgroupPath:     cfg.CgroupPath,
	})
	if err != nil {
		return err
	}
	defer manager.Close()

	redirectMgr := redirect.NewManager(manager)
	if err := redirectMgr.ExemptPID(uint32(os.Getpid())); err != nil {
		return err
	}
	if err := redirectMgr.ApplyConfig(merged); err != nil {
		return err
	}

	if redirectMgr.HasDomainRules() {
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

		sub, cancelSub := eventBus.Subscribe("dns-rules", cfg.SubscriberBuffer)
		defer cancelSub()

		collector := collector.New(reader, eventBus, logger)
		go func() {
			if err := collector.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Printf("collector stopped: %v", err)
			}
		}()

		watcher := redirect.NewDNSWatcher(redirectMgr)
		go watcher.Run(ctx, sub)
	}

	server := proxy.Server{
		ListenV4:        merged.Proxy.ListenV4,
		ListenV6:        merged.Proxy.ListenV6,
		OrigDstMap:      redirectMgr.OrigDst(),
		OrigDstPidPort:  redirectMgr.OrigDstPidPort(),
		OrigDstFlowV4:   redirectMgr.OrigDstFlowV4(),
		OrigDstFlowV6:   redirectMgr.OrigDstFlowV6(),
		Logger:          logger,
	}

	return server.Run(ctx)
}
