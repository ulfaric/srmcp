package messages

import (
	"time"
)

// Header for messages
type Header struct {
	MessageType string    `validate:"required"`
	SenderID    string    `validate:"required"`
	Timestamp   time.Time `validate:"required"`
}
