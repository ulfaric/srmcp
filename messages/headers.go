package messages

import (
	"time"
)

// Header for messages
type Header struct {
	MessageType string
	SenderID    string
	Timestamp   time.Time
}

// GetMessageType returns the message type
func (h *Header) GetMessageType() string {
	return h.MessageType
}

// SetMessageType sets the message type
func (h *Header) SetMessageType(messageType string) {
	h.MessageType = messageType
}

// GetSenderID returns the sender ID
func (h *Header) GetSenderID() string {
	return h.SenderID
}

// SetSenderID sets the sender ID
func (h *Header) SetSenderID(senderID string) {
	h.SenderID = senderID
}

// GetTimestamp returns the timestamp
func (h *Header) GetTimestamp() time.Time {
	return h.Timestamp
}

// SetTimestamp sets the timestamp
func (h *Header) SetTimestamp(timestamp time.Time) {
	h.Timestamp = timestamp
}
