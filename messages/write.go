package messages

import (
	"github.com/ulfaric/srmcp"
	"time"
)

type Write struct {
	Header Header
	NodeID string
	Data   interface{}
}

// Write message constructor
func NewWrite(SenderID string, nodeID string, data interface{}, time time.Time) *Write {
	return &Write{
		Header: Header{
			MessageType: srmcp.Write,
			SenderID:    SenderID,
			Timestamp:   time,
		},
		NodeID: nodeID,
		Data:   data,
	}
}

// Get the header of the message
func (write *Write) GetHeader() Header {
	return write.Header
}

// Get the node ID of the message
func (write *Write) GetNodeID() string {
	return write.NodeID
}