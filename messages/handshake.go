package messages

import (
	"github.com/ulfaric/srmcp"
)

type HandShake struct{
	EncryptionKey []byte
}

func NewHandShake(key []byte) *HandShake {
	return &HandShake{
		EncryptionKey: key,
	}
}

func (h *HandShake) Encode() ([]byte, error) {
	return srmcp.Serializer(h)
}

