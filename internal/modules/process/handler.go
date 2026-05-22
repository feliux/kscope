package process

import (
	"fmt"
	"os"
	"strings"

	"github.com/feliux/kscope/internal/correlation"
	"github.com/feliux/kscope/internal/events"
)

func Handle(store *correlation.Store, evt events.Event) *correlation.Signal {
	payload, ok := evt.Payload.(events.ProcessEvent)
	if !ok {
		return nil
	}

	payload.Cmdline = readCmdline(payload.PID)

	comm := payload.Comm
	if comm == "" {
		comm = evt.Comm
	}

	return store.UpsertProcess(
		payload.PID,
		payload.PPID,
		comm,
		payload.Cmdline,
		evt.Timestamp,
	)
}

func readCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}

	parts := strings.Split(string(data), "\x00")
	filtered := parts[:0]
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}

	return strings.Join(filtered, " ")
}
