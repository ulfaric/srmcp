package test

import (
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/messages"
	"testing"
	"time"
)

func TestMessageHeader(t *testing.T) {
	header := messages.Header{
		MessageType: "test",
		SenderID: "test",
		Length: 10,
	}
	header.SetTimestamp(time.Now())

	bytes, err  := srmcp.Serializer(header)
	if err != nil {
		t.Errorf("Error serializing header: %v", err)
	}
	t.Logf("Serialized header: %v", bytes)

	var h messages.Header
	srmcp.Deserializer(bytes, &h)
	if h.MessageType != header.MessageType {
		t.Errorf("Message type mismatch: %v != %v", h.MessageType, header.MessageType)
	}
	if h.SenderID != header.SenderID {
		t.Errorf("Sender ID mismatch: %v != %v", h.SenderID, header.SenderID)
	}
	if h.Timestamp != header.Timestamp {
		t.Errorf("Timestamp mismatch: %v != %v", h.Timestamp, header.Timestamp)
	}
}
