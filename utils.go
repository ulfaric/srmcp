package srmcp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"time"
)

// Serializer encodes a struct into a byte slice
func Serializer(v interface{}) ([]byte, error) {
	var encodedBytes bytes.Buffer
	val := reflect.ValueOf(v)

	// Ensure we have the actual struct value
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("EncodeStruct: expected a struct, got %s", val.Kind())
	}

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := field.Type()

		switch fieldType.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Float32, reflect.Float64, reflect.Bool:
			binary.Write(&encodedBytes, binary.BigEndian, field.Interface())

		case reflect.String:
			strBytes := []byte(field.String())
			binary.Write(&encodedBytes, binary.BigEndian, int32(len(strBytes))) // Write length
			encodedBytes.Write(strBytes) // Write string content

		case reflect.Slice:
			binary.Write(&encodedBytes, binary.BigEndian, int32(field.Len())) // Write length
			for j := 0; j < field.Len(); j++ {
				elem := field.Index(j)
				switch elem.Kind() {
				case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
					reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
					reflect.Float32, reflect.Float64, reflect.Bool:
					binary.Write(&encodedBytes, binary.BigEndian, elem.Interface())

				case reflect.String:
					elemBytes := []byte(elem.String())
					binary.Write(&encodedBytes, binary.BigEndian, int32(len(elemBytes))) // Write length
					encodedBytes.Write(elemBytes) // Write string content

				default:
					return nil, fmt.Errorf("EncodeStruct: unsupported slice element type %s", elem.Kind())
				}
			}

		default:
			return nil, fmt.Errorf("EncodeStruct: unsupported field type %s", fieldType.Kind())
		}
	}

	return encodedBytes.Bytes(), nil
}

// Deserializer decodes a byte slice into a struct
func Deserializer(data []byte, v interface{}) error {
	buf := bytes.NewBuffer(data)
	val := reflect.ValueOf(v)

	// Ensure we have a pointer to a struct
	if val.Kind() != reflect.Ptr {
		return fmt.Errorf("DecodeStruct: expected a pointer to a struct, got %s", val.Kind())
	}

	val = val.Elem()

	if val.Kind() != reflect.Struct {
		return fmt.Errorf("DecodeStruct: expected a struct, got %s", val.Kind())
	}

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := field.Type()

		switch fieldType.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Float32, reflect.Float64, reflect.Bool:
			if err := binary.Read(buf, binary.BigEndian, field.Addr().Interface()); err != nil {
				return err
			}

		case reflect.String:
			var strLen int32
			if err := binary.Read(buf, binary.BigEndian, &strLen); err != nil {
				return err
			}
			strBytes := make([]byte, strLen)
			if _, err := buf.Read(strBytes); err != nil {
				return err
			}
			field.SetString(string(strBytes))

		case reflect.Slice:
			var sliceLen int32
			if err := binary.Read(buf, binary.BigEndian, &sliceLen); err != nil {
				return err
			}
			slice := reflect.MakeSlice(fieldType, int(sliceLen), int(sliceLen))

			for j := 0; j < int(sliceLen); j++ {
				elem := slice.Index(j)

				switch elem.Kind() {
				case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
					reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
					reflect.Float32, reflect.Float64, reflect.Bool:
					if err := binary.Read(buf, binary.BigEndian, elem.Addr().Interface()); err != nil {
						return err
					}

				case reflect.String:
					var elemLen int32
					if err := binary.Read(buf, binary.BigEndian, &elemLen); err != nil {
						return err
					}
					elemBytes := make([]byte, elemLen)
					if _, err := buf.Read(elemBytes); err != nil {
						return err
					}
					elem.SetString(string(elemBytes))

				default:
					return fmt.Errorf("DecodeStruct: unsupported slice element type %s", elem.Kind())
				}
			}

			field.Set(slice)

		default:
			return fmt.Errorf("DecodeStruct: unsupported field type %s", fieldType.Kind())
		}
	}

	return nil
}


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
