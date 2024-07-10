package messages

import (
	"github.com/ulfaric/srmcp"
	"time"
)

// Read message
type Read struct {
	Header Header
	NodeID string
}

// Read message constructor
func NewRead(SenderID string, nodeID string, time time.Time) *Read {
	return &Read{
		Header: Header{
			MessageType: srmcp.Read,
			SenderID:    SenderID,
			Timestamp:   time,
		},
		NodeID: nodeID,
	}
}

// Get the header of the message
func (read *Read) GetHeader() Header {
	return read.Header
}

// Get the node ID of the message
func (read *Read) GetNodeID() string {
	return read.NodeID
}

// Set the node ID of the message
func (read *Read) SetNodeID(nodeID string) {
	read.NodeID = nodeID
}
