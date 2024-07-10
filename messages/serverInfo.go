package messages

import (
	"time"
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/node"
)


// ServerInfo message which is sent by the server to the client to provide information about the server
type ServerInfo struct {
	Header        Header
	Hostname      string
	NumberOfNodes int
	Nodes         []*node.Node
}

// ServerInfo message constructor
func NewServerInfo(SenderID string, hostname string, numberOfNodes int, nodes []*node.Node, time time.Time) *ServerInfo {
	return &ServerInfo{
		Header: Header{
			MessageType: srmcp.ServerInfo,
			SenderID:    SenderID,
			Timestamp:   time,
		},
		Hostname:      hostname,
		NumberOfNodes: numberOfNodes,
		Nodes:         nodes,
	}
}

// Get the header of the message
func (serverInfo *ServerInfo) GetHeader() Header {
	return serverInfo.Header
}

// Get the hostname of the server
func (serverInfo *ServerInfo) GetHostname() string {
	return serverInfo.Hostname
}

// Get the number of nodes in the server
func (serverInfo *ServerInfo) GetNumberOfNodes() int {
	return serverInfo.NumberOfNodes
}

// Get the nodes in the server
func (serverInfo *ServerInfo) GetNodes() []*node.Node {
	return serverInfo.Nodes
}

// Set the hostname of the server
func (serverInfo *ServerInfo) SetHostname(hostname string) {
	serverInfo.Hostname = hostname
}

// Set the number of nodes in the server
func (serverInfo *ServerInfo) SetNumberOfNodes(numberOfNodes int) {
	serverInfo.NumberOfNodes = numberOfNodes
}

// Set the nodes in the server
func (serverInfo *ServerInfo) SetNodes(nodes []*node.Node) {
	serverInfo.Nodes = nodes
}
