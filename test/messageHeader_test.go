package test

import (
	"github.com/google/uuid"
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/messages"
	"testing"
	"time"
)

func TestMessageHeader(t *testing.T) {
	id := uuid.New()
	header := messages.Header{
		MessageType: "HEL",
		SenderID:    id.String(),
		Length:      0,
	}
	header.SetTimestamp(time.Now())

	bytes, err := srmcp.Serializer(header)
	if err != nil {
		t.Errorf("Error serializing header: %v", err)
	}
	t.Logf("Serialized header Length: %v", len(bytes))

	var h messages.Header
	srmcp.Deserializer(bytes, &h)
	if h.MessageType != header.MessageType {
		t.Errorf("Message type mismatch: %v != %v", h.MessageType, header.MessageType)
	}
	t.Logf("Message type: %v", h.MessageType)
	if h.SenderID != header.SenderID {
		t.Errorf("Sender ID mismatch: %v != %v", h.SenderID, header.SenderID)
	}
	t.Logf("Sender ID: %v", h.SenderID)
	if h.Timestamp != header.Timestamp {
		t.Errorf("Timestamp mismatch: %v != %v", h.Timestamp, header.Timestamp)
	}
	t.Logf("Timestamp: %v", h.Timestamp)
}
