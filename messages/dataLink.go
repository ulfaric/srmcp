package messages

import (
	"time"

	"github.com/ulfaric/srmcp"
)

type DataLinkReq struct {
	Header Header
}

func NewDataLinkReq(SenderID string, t time.Time) *DataLinkReq {
	return &DataLinkReq{
		Header: Header{
			MessageType: srmcp.DataLinkReq,
			SenderID:    SenderID,
			Timestamp:   t.Format(time.RFC3339Nano),
			Length:      0,
		},
	}
}

func (s *DataLinkReq) Encode() ([]byte, error) {
	bytes, err := srmcp.Serializer(s)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

type DataLinkRep struct {
	DataPort uint32
}

func NewDataLinkRep(dataPort uint32) *DataLinkRep {
	return &DataLinkRep{
		DataPort: dataPort,
	}
}

func (m *DataLinkRep) Encode() ([]byte, error) {
	return srmcp.Serializer(m)
}
