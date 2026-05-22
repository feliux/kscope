package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/feliux/kscope/internal/correlation"
)

type signalWriter interface {
	Run(ctx context.Context, in <-chan correlation.Signal) error
}

func newSignalWriter(mode string, out io.Writer) (signalWriter, error) {
	switch strings.ToLower(mode) {
	case "human":
		return &humanWriter{out: out}, nil
	case "json":
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		return &jsonWriter{enc: enc}, nil
	default:
		return nil, fmt.Errorf("unknown output format: %s", mode)
	}
}

type humanWriter struct {
	out io.Writer
}

func (w *humanWriter) Run(ctx context.Context, in <-chan correlation.Signal) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case sig, ok := <-in:
			if !ok {
				return nil
			}
			switch sig.Kind {
			case correlation.SignalProcess:
				fmt.Fprintf(w.out, "[process] pid=%d ppid=%d comm=%s cmdline=%s\n", sig.PID, sig.PPID, sig.Comm, sig.Cmdline)
			case correlation.SignalDNS:
				if sig.Response {
					fmt.Fprintf(w.out, "[dns:reply] pid=%d comm=%s domain=%s type=%s answers=%v\n", sig.PID, sig.Comm, sig.Domain, sig.QueryType, sig.Answers)
				} else {
					fmt.Fprintf(w.out, "[dns:query] pid=%d comm=%s domain=%s type=%s\n", sig.PID, sig.Comm, sig.Domain, sig.QueryType)
				}
			case correlation.SignalTCP:
				if sig.Domain != "" {
					fmt.Fprintf(w.out, "[tcp] pid=%d comm=%s dst=%s:%d domain=%s success=%t\n", sig.PID, sig.Comm, sig.IP, sig.Port, sig.Domain, sig.Success)
				} else {
					fmt.Fprintf(w.out, "[tcp] pid=%d comm=%s dst=%s:%d success=%t\n", sig.PID, sig.Comm, sig.IP, sig.Port, sig.Success)
				}
			default:
				fmt.Fprintf(w.out, "[event] pid=%d comm=%s kind=%s\n", sig.PID, sig.Comm, sig.Kind)
			}
		}
	}
}

type jsonWriter struct {
	enc *json.Encoder
}

func (w *jsonWriter) Run(ctx context.Context, in <-chan correlation.Signal) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case sig, ok := <-in:
			if !ok {
				return nil
			}
			if err := w.enc.Encode(sig); err != nil {
				return err
			}
		}
	}
}
