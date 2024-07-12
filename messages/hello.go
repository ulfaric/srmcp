package messages

import (
	"time"

	"github.com/ulfaric/srmcp"
)

// Hello message
type Hello struct {
	Header Header
}

// Hello message constructor
func NewHello(SenderID string, t time.Time) *Hello {
	return &Hello{
		Header: Header{
			MessageType: srmcp.Hello,
			SenderID:    SenderID,
			Timestamp:   t.Format(time.RFC3339Nano),
		},
	}
}
