package srmcp

import (
	"bytes"
	"encoding/binary"
)

// Acknowledgement message
type ACK struct {
	MessageHeader MessageHeader
	StatusCode    uint16
}

// Encode encodes the ACK message
func (msg *ACK) Encode() []byte {
	var msg_bytes []byte
	msg_bytes = append(msg_bytes, msg.MessageHeader.Encode()...)
	binary.BigEndian.PutUint16(msg_bytes[len(msg_bytes):], uint16(msg.StatusCode))
	return msg_bytes
}

// Decode decodes the ACK message
func (msg *ACK) Decode(header []byte) {
	msg.MessageHeader.Decode(header[:27])
	msg.StatusCode = binary.BigEndian.Uint16(header[27:])
}

// GetStatusCode returns the status code
func (msg *ACK) GetStatusCode() uint16 {
	return msg.StatusCode
}

// SetStatusCode sets the status code
func (msg *ACK) SetStatusCode(statusCode uint16) {
	msg.StatusCode = statusCode
}

// Handshake message for exchanging encryption keys
type HandShake struct {
	MessageHeader MessageHeader
	EncryptionKey [32]byte
	Cipher        []byte
}

// Encode encodes the HandShake message
func (msg *HandShake) Encode() []byte {
	var msg_bytes []byte
	msg_bytes = append(msg_bytes, msg.MessageHeader.Encode()...)
	msg_bytes = append(msg_bytes, msg.EncryptionKey[:]...)
	cipher, err := Encrypt(msg.EncryptionKey[:], msg.MessageHeader.SenderID[:])
	if err != nil {
		panic(err)
	}
	copy(msg.Cipher[:], cipher)
	msg_bytes = append(msg_bytes, cipher...)
	return msg_bytes
}

// Decode decodes the HandShake message
func (msg *HandShake) Decode(msg_bytes []byte) {
	msg.MessageHeader.Decode(msg_bytes[:27])
	copy(msg.EncryptionKey[:], msg_bytes[27:59])
	cipher, err := Decrypt(msg.EncryptionKey[:], msg_bytes[59:])
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(cipher, msg.MessageHeader.SenderID[:]) {
		panic("Decryption failed")
	}
	copy(msg.Cipher[:], msg_bytes[59:])
}

// GetEncryptionKey returns the encryption key
func (msg *HandShake) GetEncryptionKey() string {
	return string(msg.EncryptionKey[:])
}

// SetEncryptionKey sets the encryption key
func (msg *HandShake) SetEncryptionKey(encryptionKey string) {
	copy(msg.EncryptionKey[:], encryptionKey)
}

// GetCipher returns the cipher
func (msg *HandShake) GetCipher() string {
	return string(msg.Cipher[:])
}

// SetCipher sets the cipher
func (msg *HandShake) SetCipher() {
	cipher, err := Encrypt(msg.EncryptionKey[:], msg.MessageHeader.SenderID[:])
	if err != nil {
		panic(err)
	}
	copy(msg.Cipher[:], cipher)
}

// Subscribe message for subscribing to a topic
type Subscribe struct {
	MessageHeader MessageHeader
	Length        uint64
	TopicBytes    uint32
	Topic         string
	NumberOfNodes uint32
	NodesBytes    uint32
	Nodes         [][16]byte
}

// Encode encodes the Subscribe message
func (msg *Subscribe) Encode(encryptionKey []byte) []byte {
	var msgBytes []byte
	msgBytes = append(msgBytes, msg.MessageHeader.Encode()...)

	msg.Length = uint64(27 + 4 + len(msg.Topic) + 4 + 4 + 16*len(msg.Nodes))
	lengthBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lengthBytes, msg.Length)
	msgBytes = append(msgBytes, lengthBytes...)

	topicBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(topicBytes, uint32(len(msg.Topic)))
	msgBytes = append(msgBytes, topicBytes...)

	msgBytes = append(msgBytes, []byte(msg.Topic)...)

	numberOfNodesBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(numberOfNodesBytes, msg.NumberOfNodes)
	msgBytes = append(msgBytes, numberOfNodesBytes...)

	nodesBytesLength := 4 + 16*len(msg.Nodes)
	nodesBytes := make([]byte, nodesBytesLength)
	binary.BigEndian.PutUint32(nodesBytes[:4], uint32(nodesBytesLength))
	msgBytes = append(msgBytes, nodesBytes[:4]...)

	for _, node := range msg.Nodes {
		msgBytes = append(msgBytes, node[:]...)
	}

	cipher, err := Encrypt(encryptionKey, msgBytes)
	if err != nil {
		panic(err)
	}

	return cipher
}

// Decode decodes the Subscribe message
func (msg *Subscribe) Decode(msgBytes, encryptionKey []byte) {
	decrypted, err := Decrypt(encryptionKey, msgBytes)
	if err != nil {
		panic(err)
	}

	msg.MessageHeader.Decode(decrypted[:27])
	msg.Length = binary.BigEndian.Uint64(decrypted[27:35])
	msg.TopicBytes = binary.BigEndian.Uint32(decrypted[35:39])
	msg.Topic = string(decrypted[39 : 39+msg.TopicBytes])
	msg.NumberOfNodes = binary.BigEndian.Uint32(decrypted[39+msg.TopicBytes : 43+msg.TopicBytes])
	msg.NodesBytes = binary.BigEndian.Uint32(decrypted[43+msg.TopicBytes : 47+msg.TopicBytes])
	msg.Nodes = make([][16]byte, msg.NumberOfNodes)

	for i := 0; i < int(msg.NumberOfNodes); i++ {
		copy(msg.Nodes[i][:], decrypted[47+int(msg.TopicBytes)+i*16:])
	}
}

// GetTopic returns the topic
func (msg *Subscribe) GetTopic() string {
	return msg.Topic
}

// SetTopic sets the topic
func (msg *Subscribe) SetTopic(topic string) {
	msg.Topic = topic
}

// GetNodes returns the nodes
func (msg *Subscribe) GetNodes() [][16]byte {
	return msg.Nodes
}

// SetNodes sets the nodes
func (msg *Subscribe) SetNodes(nodes [][16]byte) {
	msg.Nodes = nodes
}
