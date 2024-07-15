package messages

import (
	"time"

	"github.com/ulfaric/srmcp"
)

type Subscribe struct {
	Header Header
}

func NewSubscribe(SenderID string, t time.Time) *Subscribe {
	return &Subscribe{
		Header: Header{
			MessageType: srmcp.Subscribe,
			SenderID:    SenderID,
			Timestamp:   t.Format(time.RFC3339Nano),
			Length:      0,
		},
	}
}

func (s *Subscribe) Encode() ([]byte, error) {
	bytes, err := srmcp.Serializer(s)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

type SubscriptionResponse struct {
	DataPort uint32
}

func NewSubscriptionResponse(dataPort uint32) *SubscriptionResponse {
	return &SubscriptionResponse{
		DataPort: dataPort,
	}
}

func (m *SubscriptionResponse) Encode() ([]byte, error) {
	return srmcp.Serializer(m)
}
