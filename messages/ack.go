package messages

import (
	"time"
	"github.com/ulfaric/srmcp"
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
			MessageType: srmcp.ACK,
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