package messages

import (
	"time"
)

// Header for messages
type Header struct {
	MessageType string
	SenderID    string
	Timestamp   string
	Length      int32
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
	time, err := time.Parse(time.RFC3339Nano, h.Timestamp)
	if err != nil {
		panic(err)
	}
	return time
}

// SetTimestamp sets the timestamp
func (h *Header) SetTimestamp(timestamp time.Time) {
	h.Timestamp = timestamp.Format(time.RFC3339Nano)
}

// GetLength returns the length
func (h *Header) GetLength() int32 {
	return h.Length
}

// SetLength sets the length
func (h *Header) SetLength(length int32) {
	h.Length = length
}
