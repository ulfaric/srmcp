package node

import (
	"reflect"
	"sync"
)

type NodeInfo struct {
	ID       string `validate:"required"`
	Name     string `validate:"required"`
	Type     string `validate:"required"`
	Desc     string
	Parent   map[string]*NodeInfo
	Children map[string]*NodeInfo
}

type Node struct {
	ID       string
	Name     string
	Value    interface{}
	Desc     string
	Parent   map[string]*Node
	Children map[string]*Node
	mu       sync.Mutex
}

// NewNode creates a new node with the given name and value.
func NewNode(id, name string, value interface{}) *Node {
	return &Node{
		ID:       id,
		Name:     name,
		Value:    value,
		Parent:   make(map[string]*Node),
		Children: make(map[string]*Node),
	}
}

// GetName returns the name of the current node.
func (n *Node) GetName() string {
	return n.Name
}

// SetName sets the name of the current node.
func (n *Node) SetName(name string) {
	n.Name = name
}

// GetValue returns the value of the current node.
func (n *Node) GetValue() interface{} {
	return n.Value
}

// SetValue sets the value of the current node.
func (n *Node) SetValue(value interface{}) {
	n.Value = value
}

// AddChild adds a child node to the current node.
func (n *Node) AddChild(child *Node) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Children[child.ID] = child
	child.Parent[n.ID] = n
}

// RemoveChild removes a child node from the current node.
func (n *Node) RemoveChild(child *Node) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.Children, child.ID)
	delete(child.Parent, n.ID)
}

// GetChildren returns the children of the current node.
func (n *Node) GetChildren() map[string]*Node {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.Children
}

// AddParent adds a parent node to the current node.
func (n *Node) AddParent(parent *Node) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Parent[parent.ID] = parent
	parent.Children[n.ID] = n
}

// RemoveParent removes a parent node from the current node.
func (n *Node) RemoveParent(parent *Node) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.Parent, parent.ID)
	delete(parent.Children, n.ID)
}

// GetParents returns the parents of the current node.
func (n *Node) GetParents() map[string]*Node {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.Parent
}

// getNodeInfoRecursive is a helper function for GetNodeInfo to prevent infinite loops.
func getNodeInfoRecursive(node *Node, visited map[string]bool) *NodeInfo {
	if visited[node.ID] {
		return nil
	}

	visited[node.ID] = true

	// Convert Parent and Children maps to NodeInfo maps recursively
	parentInfo := make(map[string]*NodeInfo)
	for k, v := range node.Parent {
		if !visited[k] {
			parentInfo[k] = getNodeInfoRecursive(v, visited)
		}
	}

	childrenInfo := make(map[string]*NodeInfo)
	for k, v := range node.Children {
		if !visited[k] {
			childrenInfo[k] = getNodeInfoRecursive(v, visited)
		}
	}

	return &NodeInfo{
		ID:       node.ID,
		Name:     node.Name,
		Type:     reflect.TypeOf(node.Value).String(),
		Desc:     node.Desc,
		Parent:   parentInfo,
		Children: childrenInfo,
	}
}

// GetNodeInfo returns the node information of the current node.
func GetNodeInfo(node *Node) *NodeInfo {
	node.mu.Lock()
	defer node.mu.Unlock()

	visited := make(map[string]bool)
	return getNodeInfoRecursive(node, visited)
}

// ReconstructNode reconstructs a Node object from a given NodeInfo.
func ReconstructNode(info *NodeInfo) *Node {
	if info == nil {
		return nil
	}

	node := &Node{
		ID:       info.ID,
		Name:     info.Name,
		Value:    reflect.New(reflect.TypeOf(info.Type)).Elem().Interface(), // Reconstruct value from type
		Desc:     info.Desc,
		Parent:   make(map[string]*Node),
		Children: make(map[string]*Node),
	}

	// Convert Parent and Children maps from NodeInfo to Node maps recursively
	for k, v := range info.Parent {
		node.Parent[k] = ReconstructNode(v)
	}
	for k, v := range info.Children {
		node.Children[k] = ReconstructNode(v)
	}

	return node
}
