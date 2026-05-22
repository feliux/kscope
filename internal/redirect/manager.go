package redirect

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	bpfmgr "github.com/feliux/kscope/internal/ebpf"
	"golang.org/x/sys/unix"
)

var ErrInvalidRule = errors.New("invalid rule")

type Manager struct {
	rulesPid       *ciliumebpf.Map
	rulesPidExempt *ciliumebpf.Map
	rulesComm      *ciliumebpf.Map
	rulesIPV4      *ciliumebpf.Map
	rulesIPV6      *ciliumebpf.Map
	rulesDomainV4  *ciliumebpf.Map
	rulesDomainV6  *ciliumebpf.Map
	proxyTargetV4  *ciliumebpf.Map
	proxyTargetV6  *ciliumebpf.Map
	origDst        *ciliumebpf.Map
	origDstPidPort *ciliumebpf.Map
	origDstFlowV4  *ciliumebpf.Map
	origDstFlowV6  *ciliumebpf.Map
	redirectStats  *ciliumebpf.Map
	domainRulePort map[string][]uint16
}

type ruleValue struct {
	Enabled uint8
}

type domainValue struct {
	ExpiresAtNs uint64
}

type ipPortV4 struct {
	IP   uint32
	Port uint16
	Pad  uint16
}

type ipPortV6 struct {
	IP   [16]byte
	Port uint16
	Pad  uint16
}

type proxyTargetV4 struct {
	IP   uint32
	Port uint16
	Pad  uint16
}

type proxyTargetV6 struct {
	IP   [16]byte
	Port uint16
	Pad  uint16
}

func NewManager(mgr *bpfmgr.Manager) *Manager {
	return &Manager{
		rulesPid:       mgr.RulesPid(),
		rulesPidExempt: mgr.RulesPidExempt(),
		rulesComm:      mgr.RulesComm(),
		rulesIPV4:      mgr.RulesIpportV4(),
		rulesIPV6:      mgr.RulesIpportV6(),
		rulesDomainV4:  mgr.RulesDomainV4(),
		rulesDomainV6:  mgr.RulesDomainV6(),
		proxyTargetV4:  mgr.ProxyTargetV4(),
		proxyTargetV6:  mgr.ProxyTargetV6(),
		origDst:        mgr.OrigDst(),
		origDstPidPort: mgr.OrigDstPidPort(),
		origDstFlowV4:  mgr.OrigDstFlowV4(),
		origDstFlowV6:  mgr.OrigDstFlowV6(),
		redirectStats:  mgr.RedirectStats(),
		domainRulePort: make(map[string][]uint16),
	}
}

func (m *Manager) OrigDst() *ciliumebpf.Map {
	return m.origDst
}

func (m *Manager) OrigDstPidPort() *ciliumebpf.Map {
	return m.origDstPidPort
}

func (m *Manager) OrigDstFlowV4() *ciliumebpf.Map {
	return m.origDstFlowV4
}

func (m *Manager) OrigDstFlowV6() *ciliumebpf.Map {
	return m.origDstFlowV6
}

func (m *Manager) RedirectStats() *ciliumebpf.Map {
	return m.redirectStats
}

func (m *Manager) ExemptPID(pid uint32) error {
	if m.rulesPidExempt == nil {
		return nil
	}
	key := pid
	val := ruleValue{Enabled: 1}
	if err := m.rulesPidExempt.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
		return fmt.Errorf("update exempt pid: %w", err)
	}
	return nil
}

func (m *Manager) HasDomainRules() bool {
	return len(m.domainRulePort) > 0
}

func (m *Manager) ApplyConfig(cfg Config) error {
	domainRules, err := parseDomainRules(cfg.Rules.Domains)
	if err != nil {
		return err
	}
	m.domainRulePort = domainRules

	if cfg.Proxy.RedirectV4 == "" {
		return fmt.Errorf("proxy redirect v4 is empty")
	}
	if err := setProxyTarget(m.proxyTargetV4, cfg.Proxy.RedirectV4, false); err != nil {
		return err
	}
	if cfg.Proxy.RedirectV6 != "" {
		if err := setProxyTarget(m.proxyTargetV6, cfg.Proxy.RedirectV6, true); err != nil {
			return err
		}
	}

	if err := clearMap(m.rulesPid); err != nil {
		return err
	}
	if err := clearMap(m.rulesComm); err != nil {
		return err
	}
	if err := clearMap(m.rulesIPV4); err != nil {
		return err
	}
	if err := clearMap(m.rulesIPV6); err != nil {
		return err
	}
	if err := clearMap(m.rulesDomainV4); err != nil {
		return err
	}
	if err := clearMap(m.rulesDomainV6); err != nil {
		return err
	}

	for _, pid := range cfg.Rules.PIDs {
		key := pid
		val := ruleValue{Enabled: 1}
		if err := m.rulesPid.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
			return fmt.Errorf("update pid rule: %w", err)
		}
	}

	for _, comm := range cfg.Rules.Comms {
		key := commKey(comm)
		val := ruleValue{Enabled: 1}
		if err := m.rulesComm.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
			return fmt.Errorf("update comm rule: %w", err)
		}
	}

	for _, rule := range cfg.Rules.IPs {
		ip, port, err := parseIPRule(rule)
		if err != nil {
			return err
		}
		if ip4 := ip.To4(); ip4 != nil {
			key := ipPortV4{
				IP:   ipv4ToUint32(ip4),
				Port: port,
			}
			val := ruleValue{Enabled: 1}
			if err := m.rulesIPV4.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
				return fmt.Errorf("update ipv4 rule: %w", err)
			}
		} else if ip16 := ip.To16(); ip16 != nil {
			key := ipPortV6{Port: port}
			copy(key.IP[:], ip16)
			val := ruleValue{Enabled: 1}
			if err := m.rulesIPV6.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
				return fmt.Errorf("update ipv6 rule: %w", err)
			}
		}
	}

	return nil
}

func (m *Manager) UpdateDomainFromReply(domain string, answers []string, ttl uint32) error {
	if ttl == 0 {
		return nil
	}

	ports, ok := m.domainRulePort[domain]
	if !ok || len(ports) == 0 {
		return nil
	}

	now, err := monotonicNowNs()
	if err != nil {
		return err
	}

	expires := uint64(now) + uint64(ttl)*uint64(time.Second)

	val := domainValue{ExpiresAtNs: expires}

	for _, addr := range answers {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}

		if ip4 := ip.To4(); ip4 != nil {
			for _, port := range ports {
				key := ipPortV4{
					IP:   ipv4ToUint32(ip4),
					Port: port,
				}
				if err := m.rulesDomainV4.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
					return fmt.Errorf("update domain ipv4 rule: %w", err)
				}
			}
			continue
		}

		if ip16 := ip.To16(); ip16 != nil {
			for _, port := range ports {
				key := ipPortV6{Port: port}
				copy(key.IP[:], ip16)
				if err := m.rulesDomainV6.Update(&key, &val, ciliumebpf.UpdateAny); err != nil {
					return fmt.Errorf("update domain ipv6 rule: %w", err)
				}
			}
		}
	}

	return nil
}

func parseDomainRules(entries []string) (map[string][]uint16, error) {
	out := make(map[string]map[uint16]struct{})
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		domain := entry
		var port uint16 = 0

		if idx := strings.LastIndex(entry, ":"); idx != -1 {
			domain = strings.TrimSpace(entry[:idx])
			if domain == "" {
				return nil, fmt.Errorf("%w: %s", ErrInvalidRule, entry)
			}
			p, err := strconv.Atoi(entry[idx+1:])
			if err != nil || p < 0 || p > 65535 {
				return nil, fmt.Errorf("%w: %s", ErrInvalidRule, entry)
			}
			port = uint16(p)
		}

		if out[domain] == nil {
			out[domain] = make(map[uint16]struct{})
		}
		out[domain][port] = struct{}{}
	}

	result := make(map[string][]uint16, len(out))
	for domain, ports := range out {
		list := make([]uint16, 0, len(ports))
		for p := range ports {
			list = append(list, p)
		}
		result[domain] = list
	}

	return result, nil
}

func parseIPRule(raw string) (net.IP, uint16, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, 0, fmt.Errorf("%w: empty", ErrInvalidRule)
	}

	if strings.Contains(raw, ":") {
		host, portStr, err := net.SplitHostPort(raw)
		if err == nil {
			ip := net.ParseIP(host)
			if ip == nil {
				return nil, 0, fmt.Errorf("%w: %s", ErrInvalidRule, raw)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 0 || port > 65535 {
				return nil, 0, fmt.Errorf("%w: %s", ErrInvalidRule, raw)
			}
			return ip, uint16(port), nil
		}
	}

	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, 0, fmt.Errorf("%w: %s", ErrInvalidRule, raw)
	}
	return ip, 0, nil
}

func setProxyTarget(m *ciliumebpf.Map, addr string, v6 bool) error {
	if addr == "" {
		return fmt.Errorf("proxy address is empty")
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse proxy address %q: %w", addr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid proxy port: %s", portStr)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid proxy host: %s", host)
	}

	key := uint32(0)

	if v6 {
		ip16 := ip.To16()
		if ip16 == nil || ip.To4() != nil {
			return fmt.Errorf("proxy address is not IPv6: %s", addr)
		}
		val := proxyTargetV6{Port: uint16(port)}
		copy(val.IP[:], ip16)
		return m.Update(&key, &val, ciliumebpf.UpdateAny)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("proxy address is not IPv4: %s", addr)
	}
	val := proxyTargetV4{
		IP:   ipv4ToUint32(ip4),
		Port: uint16(port),
	}
	return m.Update(&key, &val, ciliumebpf.UpdateAny)
}

func clearMap(m *ciliumebpf.Map) error {
	if m == nil {
		return nil
	}

	iter := m.Iterate()
	var key []byte
	var value []byte
	for iter.Next(&key, &value) {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return iter.Err()
}

func commKey(comm string) [16]byte {
	var out [16]byte
	copy(out[:], comm)
	return out
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
}

func ipv4ToUint32BE(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func monotonicNowNs() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return int64(ts.Sec)*int64(time.Second) + int64(ts.Nsec), nil
}
