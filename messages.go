package srmcp

import (
	"time"
)

// Acknowledgement message
type ACK struct {
	Header     Header
	StatusCode int
}

// Acknowledgement message constructor
func NewACK(SenderID string, statusCode int, time time.Time) *ACK {
	return &ACK{
		Header: Header{
			MessageType: "ACK",
			SenderID:    SenderID,
			Timestamp:   time,
		},
		StatusCode: statusCode,
	}
}

// Get the header of the message
func (ack *ACK) GetHeader() Header {
	return ack.Header
}

// Get the status code of the message
func (ack *ACK) GetStatusCode() int {
	return ack.StatusCode
}

// Set the status code of the message
func (ack *ACK) SetStatusCode(statusCode int) {
	ack.StatusCode = statusCode
}



// ServerInfo message which is sent by the server to the client to provide information about the server
type ServerInfo struct {
	Header        Header
	Hostname      string
	NumberOfNodes int
	Nodes         []*Node
}

// ServerInfo message constructor
func NewServerInfo(SenderID string, hostname string, numberOfNodes int, nodes []*Node, time time.Time) *ServerInfo {
	return &ServerInfo{
		Header: Header{
			MessageType: "ServerInfo",
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
func (serverInfo *ServerInfo) GetNodes() []*Node {
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
func (serverInfo *ServerInfo) SetNodes(nodes []*Node) {
	serverInfo.Nodes = nodes
}
