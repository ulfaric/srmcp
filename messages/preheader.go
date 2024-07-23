package messages

import "encoding/binary"

type PreHeader struct {
	HeaderLength uint32
	BodyLength   uint32
}

func (ph *PreHeader) Serialize() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[:4], ph.HeaderLength)
	binary.BigEndian.PutUint32(buf[4:], ph.BodyLength)
	return buf
}