package main

import (
	"fmt"
	"strconv"
	"strings"
)

type moduleSet struct {
	dns     bool
	tcp     bool
	process bool
}

func parseModules(raw string) (moduleSet, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "all") {
		return moduleSet{dns: true, tcp: true, process: true}, nil
	}

	parts := strings.Split(trimmed, ",")
	var mods moduleSet
	for _, part := range parts {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "" {
			continue
		}
		switch p {
		case "dns":
			mods.dns = true
		case "tcp":
			mods.tcp = true
		case "process":
			mods.process = true
		case "all":
			return moduleSet{dns: true, tcp: true, process: true}, nil
		default:
			return moduleSet{}, fmt.Errorf("unknown module: %s", p)
		}
	}

	if !mods.dns && !mods.tcp && !mods.process {
		return moduleSet{}, fmt.Errorf("no modules selected")
	}

	return mods, nil
}

func parsePIDList(values []string) ([]uint32, error) {
	if len(values) == 0 {
		return nil, nil
	}

	out := make([]uint32, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid pid %q", value)
		}
		out = append(out, uint32(parsed))
	}
	return out, nil
}
