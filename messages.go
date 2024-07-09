package srmcp

import (
	"bytes"
	"encoding/binary"
	"time"
)

type ServerInfo struct {
	MessageHeader MessageHeader
	Length        uint16
	NumNodes      uint16
	NodesID       [][16]byte
}

// Encode encodes the ServerInfo message
func (msg *ServerInfo) Encode(encryptionKey []byte) []byte {
	var msg_bytes []byte
	header := msg.MessageHeader.Encode()
	msg_bytes = append(msg_bytes, header...)
	msg.Length = uint16(len(header) + 4 + 16*len(msg.NodesID))
	binary.BigEndian.PutUint16(msg_bytes[len(msg_bytes):], msg.Length)
	if msg.NumNodes > 4092 {
		panic("Too many nodes")
	}
	binary.BigEndian.PutUint16(msg_bytes[len(msg_bytes):], msg.NumNodes)
	for _, node := range msg.NodesID {
		msg_bytes = append(msg_bytes, node[:]...)
	}
	cipher, err := Encrypt(encryptionKey, msg_bytes)
	if err != nil {
		panic(err)
	}
	return cipher
}

// Decode decodes the ServerInfo message
func (msg *ServerInfo) Decode(msg_bytes []byte, encryptionKey []byte) {
	cipher, err := Decrypt(encryptionKey, msg_bytes)
	if err != nil {
		panic(err)
	}
	msg.MessageHeader.Decode(cipher[:27])
	msg.Length = binary.BigEndian.Uint16(cipher[27:])
	msg.NumNodes = binary.BigEndian.Uint16(cipher[29:])
	for i := 0; i < int(msg.NumNodes); i++ {
		var node [16]byte
		copy(node[:], cipher[31+i*16:47+i*16])
		msg.NodesID = append(msg.NodesID, node)
	}
}

// GetLength returns the length
func (msg *ServerInfo) GetLength() uint16 {
	return msg.Length
}

// SetLength sets the length
func (msg *ServerInfo) SetLength(length uint16) {
	msg.Length = length
}

// GetNumNodes returns the number of nodes
func (msg *ServerInfo) GetNumNodes() uint16 {
	return msg.NumNodes
}

// SetNumNodes sets the number of nodes
func (msg *ServerInfo) SetNumNodes(numNodes uint16) {
	msg.NumNodes = numNodes
}

// GetNodesID returns the nodes ID
func (msg *ServerInfo) GetNodesID() [][16]byte {
	return msg.NodesID
}

// SetNodesID sets the nodes ID
func (msg *ServerInfo) SetNodesID(nodesID [][16]byte) {
	msg.NodesID = nodesID
}

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

// Subscribe message for subscribing to a node
type Subscribe struct {
	MessageHeader MessageHeader
	NodeID        [16]byte
	Interval      uint64
	Duration      uint64
}

// Encode encodes the Subscribe message
func (msg *Subscribe) Encode(encryptionKey []byte) []byte {
	var msg_bytes []byte
	msg_bytes = append(msg_bytes, msg.MessageHeader.Encode()...)
	msg_bytes = append(msg_bytes, msg.NodeID[:]...)
	binary.BigEndian.PutUint64(msg_bytes[len(msg_bytes):], msg.Interval)
	binary.BigEndian.PutUint64(msg_bytes[len(msg_bytes):], msg.Duration)
	cipher, err := Encrypt(encryptionKey, msg.NodeID[:])
	if err != nil {
		panic(err)
	}
	return cipher
}

// Decode decodes the Subscribe message
func (msg *Subscribe) Decode(msg_bytes []byte, encryptionKey []byte) {
	cipher, err := Decrypt(encryptionKey, msg_bytes)
	if err != nil {
		panic(err)
	}
	msg.MessageHeader.Decode(cipher[:27])
	copy(msg.NodeID[:], cipher[27:43])
	msg.Interval = binary.BigEndian.Uint64(cipher[43:])
	msg.Duration = binary.BigEndian.Uint64(cipher[51:])
}

// GetNodeID returns the node ID
func (msg *Subscribe) GetNodeID() string {
	return string(msg.NodeID[:])
}

// SetNodeID sets the node ID
func (msg *Subscribe) SetNodeID(nodeID string) {
	copy(msg.NodeID[:], nodeID)
}

// GetInterval returns the interval
func (msg *Subscribe) GetInterval() uint64 {
	return msg.Interval
}

// SetInterval sets the interval
func (msg *Subscribe) SetInterval(interval uint64) {
	msg.Interval = interval
}

// GetDuration returns the duration
func (msg *Subscribe) GetDuration() uint64 {
	return msg.Duration
}

// SetDuration sets the duration
func (msg *Subscribe) SetDuration(duration uint64) {
	msg.Duration = duration
}

// UnSubscribe message for unsubscribing from a node
type UnSubscribe struct {
	MessageHeader MessageHeader
	NodeID        [16]byte
}

// Encode encodes the UnSubscribe message
func (msg *UnSubscribe) Encode(encryptionKey []byte) []byte {
	var msg_bytes []byte
	msg_bytes = append(msg_bytes, msg.MessageHeader.Encode()...)
	msg_bytes = append(msg_bytes, msg.NodeID[:]...)
	cipher, err := Encrypt(encryptionKey, msg_bytes)
	if err != nil {
		panic(err)
	}
	return cipher
}

// Decode decodes the UnSubscribe message
func (msg *UnSubscribe) Decode(msg_bytes []byte, encryptionKey []byte) {
	cipher, err := Decrypt(encryptionKey, msg_bytes)
	if err != nil {
		panic(err)
	}
	msg.MessageHeader.Decode(cipher[:27])
	copy(msg.NodeID[:], cipher[27:43])
}

// GetNodeID returns the node ID
func (msg *UnSubscribe) GetNodeID() string {
	return string(msg.NodeID[:])
}

// SetNodeID sets the node ID
func (msg *UnSubscribe) SetNodeID(nodeID string) {
	copy(msg.NodeID[:], nodeID)
}

// Data message for sending data
type Data struct {
	MessageHeader MessageHeader
	NodeID        [16]byte
	SourceTime    [8]byte
	ServerTime    [8]byte
	DataType      uint16
	Data          []byte
}

// Encode encodes the Data message
func (msg *Data) Encode(encryptionKey []byte) []byte {
	var msg_bytes []byte
	msg_bytes = append(msg_bytes, msg.MessageHeader.Encode()...)
	msg_bytes = append(msg_bytes, msg.NodeID[:]...)
	msg_bytes = append(msg_bytes, msg.SourceTime[:]...)
	msg_bytes = append(msg_bytes, msg.ServerTime[:]...)
	binary.BigEndian.PutUint16(msg_bytes[len(msg_bytes):], msg.DataType)
	msg_bytes = append(msg_bytes, msg.Data...)
	cipher, err := Encrypt(encryptionKey, msg_bytes)
	if err != nil {
		panic(err)
	}
	return cipher
}

// Decode decodes the Data message
func (msg *Data) Decode(msg_bytes []byte, encryptionKey []byte) {
	cipher, err := Decrypt(encryptionKey, msg_bytes)
	if err != nil {
		panic(err)
	}
	msg.MessageHeader.Decode(cipher[:27])
	copy(msg.NodeID[:], cipher[27:43])
	copy(msg.SourceTime[:], cipher[43:51])
	copy(msg.ServerTime[:], cipher[51:59])
	msg.DataType = binary.BigEndian.Uint16(cipher[59:])
	msg.Data = cipher[61:]
}

// GetNodeID returns the node ID
func (msg *Data) GetNodeID() string {
	return string(msg.NodeID[:])
}

// SetNodeID sets the node ID
func (msg *Data) SetNodeID(nodeID string) {
	copy(msg.NodeID[:], nodeID)
}

// GetSourceTime returns the source time
func (msg *Data) GetSourceTime() (time.Time, error) {
	timestamp, err := BytesToTimestamp(msg.SourceTime[:])
	return timestamp, err
}

// SetSourceTime sets the source time
func (msg *Data) SetSourceTime(t time.Time) {
	timestamp, _ := TimestampToBytes(t)
	copy(msg.SourceTime[:], timestamp)
}

// GetServerTime returns the server time
func (msg *Data) GetServerTime() (time.Time, error) {
	timestamp, err := BytesToTimestamp(msg.ServerTime[:])
	return timestamp, err
}

// SetServerTime sets the server time
func (msg *Data) SetServerTime(t time.Time) {
	timestamp, _ := TimestampToBytes(t)
	copy(msg.ServerTime[:], timestamp)
}

// GetDataType returns the data type
func (msg *Data) GetDataType() uint16 {
	return msg.DataType
}

// SetDataType sets the data type
func (msg *Data) SetDataType(dataType uint16) {
	msg.DataType = dataType
}

// GetData returns the data
func (msg *Data) GetData() []byte {
	return msg.Data
}

// SetData sets the data
func (msg *Data) SetData(data []byte) {
	msg.Data = data
}
