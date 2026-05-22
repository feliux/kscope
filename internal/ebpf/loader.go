package ebpf

import (
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Options struct {
	EnableDNS      bool
	EnableTCP      bool
	EnableProcess  bool
	EnableRedirect bool
	CgroupPath     string
}

type Manager struct {
	objs  kscopeObjects
	links []link.Link
	opts  Options
}

func LoadAndAttach(opts Options) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	opts = normalizeOptions(opts)

	var objs kscopeObjects
	if err := loadKscopeObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	manager := &Manager{objs: objs, opts: opts}

	if err := manager.attach(opts); err != nil {
		manager.Close()
		return nil, err
	}

	return manager, nil
}

func (m *Manager) Events() *ciliumebpf.Map {
	return m.objs.Events
}

func (m *Manager) RulesPid() *ciliumebpf.Map {
	return m.objs.RulesPid
}

func (m *Manager) RulesPidExempt() *ciliumebpf.Map {
	return m.objs.RulesPidExempt
}

func (m *Manager) RulesComm() *ciliumebpf.Map {
	return m.objs.RulesComm
}

func (m *Manager) RulesIpportV4() *ciliumebpf.Map {
	return m.objs.RulesIpportV4
}

func (m *Manager) RulesIpportV6() *ciliumebpf.Map {
	return m.objs.RulesIpportV6
}

func (m *Manager) RulesDomainV4() *ciliumebpf.Map {
	return m.objs.RulesDomainV4
}

func (m *Manager) RulesDomainV6() *ciliumebpf.Map {
	return m.objs.RulesDomainV6
}

func (m *Manager) ProxyTargetV4() *ciliumebpf.Map {
	return m.objs.ProxyTargetV4
}

func (m *Manager) ProxyTargetV6() *ciliumebpf.Map {
	return m.objs.ProxyTargetV6
}

func (m *Manager) OrigDst() *ciliumebpf.Map {
	return m.objs.OrigDst
}

func (m *Manager) OrigDstFlowV4() *ciliumebpf.Map {
	return m.objs.OrigDstFlowV4
}

func (m *Manager) OrigDstFlowV6() *ciliumebpf.Map {
	return m.objs.OrigDstFlowV6
}

func (m *Manager) OrigDstPidPort() *ciliumebpf.Map {
	return m.objs.OrigDstPidPort
}

func (m *Manager) RedirectStats() *ciliumebpf.Map {
	return m.objs.RedirectStats
}

func (m *Manager) Close() error {
	var outErr error

	for _, l := range m.links {
		if err := l.Close(); err != nil && outErr == nil {
			outErr = err
		}
	}

	if err := m.objs.Close(); err != nil && outErr == nil {
		outErr = err
	}

	return outErr
}

func (m *Manager) attach(opts Options) error {
	var links []link.Link

	attach := func(label string, l link.Link, err error) error {
		if err != nil {
			return fmt.Errorf("attach %s: %w", label, err)
		}
		links = append(links, l)
		return nil
	}

	if opts.EnableTCP || opts.EnableRedirect {
		kp1, err := link.Kprobe("tcp_v4_connect", m.objs.KprobeTcpV4Connect, nil)
		if err := attach("kprobe tcp_v4_connect", kp1, err); err != nil {
			return err
		}

		kp2, err := link.Kretprobe("tcp_v4_connect", m.objs.KretprobeTcpV4Connect, nil)
		if err := attach("kretprobe tcp_v4_connect", kp2, err); err != nil {
			return err
		}

		kp3, err := link.Kprobe("tcp_v6_connect", m.objs.KprobeTcpV6Connect, nil)
		if err := attach("kprobe tcp_v6_connect", kp3, err); err != nil {
			return err
		}

		kp4, err := link.Kretprobe("tcp_v6_connect", m.objs.KretprobeTcpV6Connect, nil)
		if err := attach("kretprobe tcp_v6_connect", kp4, err); err != nil {
			return err
		}
	}

	if opts.EnableRedirect {
		path := opts.CgroupPath
		if path == "" {
			path = "/sys/fs/cgroup"
		}

		cg4, err := link.AttachCgroup(link.CgroupOptions{
			Path:    path,
			Attach:  ciliumebpf.AttachCGroupInet4Connect,
			Program: m.objs.CgroupConnect4,
		})
		if err := attach("cgroup connect4", cg4, err); err != nil {
			return err
		}

		cg6, err := link.AttachCgroup(link.CgroupOptions{
			Path:    path,
			Attach:  ciliumebpf.AttachCGroupInet6Connect,
			Program: m.objs.CgroupConnect6,
		})
		if err := attach("cgroup connect6", cg6, err); err != nil {
			return err
		}
	}

	if opts.EnableDNS {
		tp1, err := link.Tracepoint("syscalls", "sys_enter_sendto", m.objs.TracepointSysEnterSendto, nil)
		if err := attach("tracepoint sys_enter_sendto", tp1, err); err != nil {
			return err
		}

		tp2, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", m.objs.TracepointSysEnterRecvfrom, nil)
		if err := attach("tracepoint sys_enter_recvfrom", tp2, err); err != nil {
			return err
		}

		tp3, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", m.objs.TracepointSysExitRecvfrom, nil)
		if err := attach("tracepoint sys_exit_recvfrom", tp3, err); err != nil {
			return err
		}
	}

	if opts.EnableProcess {
		tp4, err := link.Tracepoint("sched", "sched_process_exec", m.objs.TracepointSchedProcessExec, nil)
		if err := attach("tracepoint sched_process_exec", tp4, err); err != nil {
			return err
		}
	}

	m.links = links
	return nil
}

func normalizeOptions(opts Options) Options {
	if !opts.EnableDNS && !opts.EnableTCP && !opts.EnableProcess && !opts.EnableRedirect {
		opts.EnableDNS = true
		opts.EnableTCP = true
		opts.EnableProcess = true
	}
	return opts
}
