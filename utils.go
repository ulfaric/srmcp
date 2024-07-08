package srmcp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Converts a time.Time object to a byte array
func TimestampToBytes(t time.Time) ([]byte, error) {
	// Convert time to Unix time (number of seconds since January 1, 1970 UTC)
	unixTime := t.Unix()
	// Create a buffer to write the bytes to
	buf := new(bytes.Buffer)
	// Write the Unix time to the buffer as bytes
	err := binary.Write(buf, binary.BigEndian, unixTime)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Converts a byte array back to a time.Time object
func BytesToTimestamp(b []byte) (time.Time, error) {
	// Create a buffer to read the bytes from
	buf := bytes.NewBuffer(b)
	// Read the Unix time from the buffer
	var unixTime int64
	err := binary.Read(buf, binary.BigEndian, &unixTime)
	if err != nil {
		return time.Time{}, err
	}
	// Convert Unix time to time.Time
	t := time.Unix(unixTime, 0)
	return t, nil
}


// GenerateRandomKey generates a random 32-byte key for AES-256
func GenerateRandomKey() ([]byte, error) {
    key := make([]byte, 32)
    _, err := rand.Read(key)
    if err != nil {
        return nil, err
    }
    return key, nil
}

// Encrypt encrypts a message using AES-256-GCM
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts a message using AES-256-GCM
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
