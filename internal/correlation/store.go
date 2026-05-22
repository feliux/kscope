package correlation

import (
	"fmt"
	"sync"
	"time"

	"github.com/feliux/kscope/internal/graph"
)

type Store struct {
	mu           sync.RWMutex
	processes    map[uint32]*ProcessContext
	graph        *graph.Graph
	globalDomain map[string]map[string]int64
	globalIP     map[string]map[string]int64
}

func NewStore() *Store {
	return &Store{
		processes:    make(map[uint32]*ProcessContext),
		graph:        graph.New(),
		globalDomain: make(map[string]map[string]int64),
		globalIP:     make(map[string]map[string]int64),
	}
}

func (s *Store) Graph() *graph.Graph {
	return s.graph
}

func (s *Store) UpsertProcess(pid, ppid uint32, comm, cmdline string, ts int64) *Signal {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := s.getOrCreateProcessLocked(pid, comm)
	ctx.PPID = ppid
	if comm != "" {
		ctx.Comm = comm
	}
	if cmdline != "" {
		ctx.Cmdline = cmdline
	}

	processID := processNodeID(pid)
	s.graph.UpsertNode(processID, graph.NodeProcess, ctx.Comm)

	if ppid > 0 {
		parentID := processNodeID(ppid)
		s.graph.UpsertNode(parentID, graph.NodeProcess, "")
		s.graph.AddEdge(processID, parentID, graph.EdgeSpawnedBy)
	}

	return &Signal{
		Kind:      SignalProcess,
		Timestamp: ts,
		PID:       pid,
		PPID:      ppid,
		Comm:      ctx.Comm,
		Cmdline:   ctx.Cmdline,
	}
}

func (s *Store) AddDNSQuery(pid uint32, comm, domain, qtype string, ts int64) *Signal {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := s.getOrCreateProcessLocked(pid, comm)
	if ctx.DNS == nil {
		ctx.DNS = make(map[string][]string)
	}
	if _, ok := ctx.DNS[domain]; !ok {
		ctx.DNS[domain] = []string{}
	}

	processID := processNodeID(pid)
	domainID := domainNodeID(domain)
	s.graph.UpsertNode(processID, graph.NodeProcess, ctx.Comm)
	s.graph.UpsertNode(domainID, graph.NodeDomain, domain)
	s.graph.AddEdge(processID, domainID, graph.EdgeResolvesTo)

	return &Signal{
		Kind:      SignalDNS,
		Timestamp: ts,
		PID:       pid,
		Comm:      ctx.Comm,
		Domain:    domain,
		QueryType: qtype,
		Response:  false,
	}
}

func (s *Store) AddDNSReply(pid uint32, comm, domain, qtype string, answers []string, ttl uint32, ts int64) *Signal {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := s.getOrCreateProcessLocked(pid, comm)
	if ctx.DNS == nil {
		ctx.DNS = make(map[string][]string)
	}
	if ctx.IPToDomain == nil {
		ctx.IPToDomain = make(map[string]string)
	}

	ctx.DNS[domain] = answers
	for _, ip := range answers {
		ctx.IPToDomain[ip] = domain
	}

	if ttl > 0 {
		s.addGlobalDNSLocked(domain, answers, ttl, ts)
	}

	processID := processNodeID(pid)
	domainID := domainNodeID(domain)
	s.graph.UpsertNode(processID, graph.NodeProcess, ctx.Comm)
	s.graph.UpsertNode(domainID, graph.NodeDomain, domain)
	s.graph.AddEdge(processID, domainID, graph.EdgeResolvesTo)

	for _, ip := range answers {
		ipID := ipNodeID(ip)
		s.graph.UpsertNode(ipID, graph.NodeIP, ip)
		s.graph.AddEdge(domainID, ipID, graph.EdgeResolvesTo)
	}

	return &Signal{
		Kind:      SignalDNS,
		Timestamp: ts,
		PID:       pid,
		Comm:      ctx.Comm,
		Domain:    domain,
		QueryType: qtype,
		Response:  true,
		Answers:   answers,
	}
}

func (s *Store) AddTCPConnect(pid uint32, comm, srcIP string, srcPort uint16, dstIP string, dstPort uint16, success bool, ts int64) *Signal {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := s.getOrCreateProcessLocked(pid, comm)
	domain := ctx.IPToDomain[dstIP]
	if domain == "" {
		domain = s.lookupDomainByIPLocked(dstIP, ts)
	}

	ctx.Connections = append(ctx.Connections, TCPConn{
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Domain:    domain,
		Success:   success,
		Timestamp: ts,
	})

	processID := processNodeID(pid)
	ipID := ipNodeID(dstIP)
	serviceID := serviceNodeID(dstIP, dstPort)

	s.graph.UpsertNode(processID, graph.NodeProcess, ctx.Comm)
	s.graph.UpsertNode(ipID, graph.NodeIP, dstIP)
	s.graph.UpsertNode(serviceID, graph.NodeService, fmt.Sprintf("%s:%d", dstIP, dstPort))
	s.graph.AddEdge(processID, serviceID, graph.EdgeConnectsTo)
	s.graph.AddEdge(processID, ipID, graph.EdgeConnectsTo)

	if domain != "" {
		domainID := domainNodeID(domain)
		s.graph.UpsertNode(domainID, graph.NodeDomain, domain)
		s.graph.AddEdge(domainID, serviceID, graph.EdgeResolvesTo)
	}

	return &Signal{
		Kind:      SignalTCP,
		Timestamp: ts,
		PID:       pid,
		Comm:      ctx.Comm,
		Domain:    domain,
		IP:        dstIP,
		Port:      dstPort,
		Success:   success,
	}
}

func (s *Store) getOrCreateProcessLocked(pid uint32, comm string) *ProcessContext {
	ctx, ok := s.processes[pid]
	if !ok {
		ctx = &ProcessContext{
			PID:        pid,
			Comm:       comm,
			DNS:        make(map[string][]string),
			IPToDomain: make(map[string]string),
		}
		s.processes[pid] = ctx
	}
	if ctx.Comm == "" && comm != "" {
		ctx.Comm = comm
	}
	return ctx
}

func (s *Store) addGlobalDNSLocked(domain string, ips []string, ttl uint32, now int64) {
	if domain == "" || ttl == 0 || len(ips) == 0 {
		return
	}

	expiresAt := now + int64(ttl)*int64(time.Second)
	if expiresAt <= now {
		return
	}

	ipMap, ok := s.globalDomain[domain]
	if !ok {
		ipMap = make(map[string]int64)
		s.globalDomain[domain] = ipMap
	}

	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if current, ok := ipMap[ip]; !ok || expiresAt > current {
			ipMap[ip] = expiresAt
		}

		domainMap, ok := s.globalIP[ip]
		if !ok {
			domainMap = make(map[string]int64)
			s.globalIP[ip] = domainMap
		}
		if current, ok := domainMap[domain]; !ok || expiresAt > current {
			domainMap[domain] = expiresAt
		}
	}
}

func (s *Store) lookupDomainByIPLocked(ip string, now int64) string {
	if ip == "" {
		return ""
	}

	domainMap, ok := s.globalIP[ip]
	if !ok {
		return ""
	}

	var chosen string
	var bestExpiry int64
	var expired []string

	for domain, exp := range domainMap {
		if exp <= now {
			expired = append(expired, domain)
			continue
		}
		if exp > bestExpiry {
			bestExpiry = exp
			chosen = domain
		}
	}

	for _, domain := range expired {
		s.deleteGlobalPairLocked(domain, ip)
	}

	return chosen
}

func (s *Store) deleteGlobalPairLocked(domain, ip string) {
	if domain == "" || ip == "" {
		return
	}

	if ipMap, ok := s.globalDomain[domain]; ok {
		delete(ipMap, ip)
		if len(ipMap) == 0 {
			delete(s.globalDomain, domain)
		}
	}

	if domainMap, ok := s.globalIP[ip]; ok {
		delete(domainMap, domain)
		if len(domainMap) == 0 {
			delete(s.globalIP, ip)
		}
	}
}

func processNodeID(pid uint32) string {
	return fmt.Sprintf("process:%d", pid)
}

func domainNodeID(domain string) string {
	return fmt.Sprintf("domain:%s", domain)
}

func ipNodeID(ip string) string {
	return fmt.Sprintf("ip:%s", ip)
}

func serviceNodeID(ip string, port uint16) string {
	return fmt.Sprintf("service:%s:%d", ip, port)
}
