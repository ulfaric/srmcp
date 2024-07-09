package srmcp

import (
	"time"
	"reflect"
	"bytes"
	"encoding/binary"
)

type Header struct {}

func (h *Header) Encode() []byte {
	var encodedBytes bytes.Buffer
	head := reflect.ValueOf(h).Elem()

	for i := 0; i < head.NumField(); i++ {
		field := head.Field(i)
		fieldType := field.Type()

		switch fieldType.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Float32, reflect.Float64, reflect.Bool:
			binary.Write(&encodedBytes, binary.BigEndian, field.Interface())

		case reflect.String:
			encodedBytes.WriteString(field.String()) // Directly write string content

		case reflect.Slice:
			if fieldType.Elem().Kind() == reflect.Uint8 { // Handle []byte separately
				encodedBytes.Write(field.Bytes()) // Directly write slice content
			}

		default:
			panic("unsupported field type")
		}
	}

	return encodedBytes.Bytes()
}

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



