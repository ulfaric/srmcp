package srmcp

import (
	"time"
)

// MessageHeader is the header of the message
type MessageHeader struct {
	MessageType [3]byte
	SenderID    [16]byte
	Timestamp   [8]byte
}

// Encode encodes the message header
func (msg *MessageHeader) Encode() []byte {
	var header []byte
	header = append(header, msg.MessageType[:]...)
	header = append(header, msg.SenderID[:]...)
	header = append(header, msg.Timestamp[:]...)
	return header
}

// Decode decodes the message header
func (msg *MessageHeader) Decode(header []byte) {
	copy(msg.MessageType[:], header[:3])
	copy(msg.SenderID[:], header[3:19])
	copy(msg.Timestamp[:], header[19:27])
}

// GetMessageType returns the message type
func (msg *MessageHeader) GetMessageType() string {
	return string(msg.MessageType[:])
}

// GetSenderID returns the sender ID
func (msg *MessageHeader) GetSenderID() string {
	return string(msg.SenderID[:])
}

// GetTimestamp returns the timestamp
func (msg *MessageHeader) GetTimestamp() (time.Time, error) {
	timestamp, err := BytesToTimestamp(msg.Timestamp[:])
	return timestamp, err

}

// SetMessageType sets the message type
func (msg *MessageHeader) SetMessageType(messageType string) {
	copy(msg.MessageType[:], messageType)
}

// SetSenderID sets the sender ID
func (msg *MessageHeader) SetSenderID(senderID string) {
	copy(msg.SenderID[:], senderID)
}

// SetTimestamp sets the timestamp
func (msg *MessageHeader) SetTimestamp(t time.Time) {
	timestamp, _ := TimestampToBytes(t)
	copy(msg.Timestamp[:], timestamp)
}



