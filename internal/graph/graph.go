package graph

import "sync"

type NodeType string

const (
	NodeProcess NodeType = "process"
	NodeDomain  NodeType = "domain"
	NodeIP      NodeType = "ip"
	NodeService NodeType = "service"
)

type EdgeType string

const (
	EdgeResolvesTo EdgeType = "resolves_to"
	EdgeConnectsTo EdgeType = "connects_to"
	EdgeSpawnedBy  EdgeType = "spawned_by"
)

type Node struct {
	ID    string
	Type  NodeType
	Label string
}

type Edge struct {
	From string
	To   string
	Type EdgeType
}

type Graph struct {
	mu    sync.RWMutex
	nodes map[string]Node
	edges map[string]Edge
}

func New() *Graph {
	return &Graph{
		nodes: make(map[string]Node),
		edges: make(map[string]Edge),
	}
}

func (g *Graph) UpsertNode(id string, nodeType NodeType, label string) {
	if id == "" {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	node := g.nodes[id]
	node.ID = id
	node.Type = nodeType
	if label != "" {
		node.Label = label
	}
	g.nodes[id] = node
}

func (g *Graph) AddEdge(from, to string, edgeType EdgeType) {
	if from == "" || to == "" {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	key := edgeKey(from, to, edgeType)
	g.edges[key] = Edge{
		From: from,
		To:   to,
		Type: edgeType,
	}
}

func (g *Graph) Snapshot() ([]Node, []Edge) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, node)
	}

	edges := make([]Edge, 0, len(g.edges))
	for _, edge := range g.edges {
		edges = append(edges, edge)
	}

	return nodes, edges
}

func edgeKey(from, to string, edgeType EdgeType) string {
	return from + "->" + to + ":" + string(edgeType)
}
