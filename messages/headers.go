package messages

import (
	"time"
)

// Header for messages
type Header struct {
	MessageType string
	SenderID    string
	Timestamp   time.Time
	Length      uint32
}


