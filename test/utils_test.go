package test

import (
	"bytes"
	"encoding/binary"
	"github.com/ulfaric/srmcp"
	"reflect"
	"testing"
)

// TestSerializer tests the Serializer function with a struct containing various field types, including lengths for strings and slices.
func TestSerializer(t *testing.T) {
	type TestStruct struct {
		Age    uint32
		Weight float64
		Active bool
		Name   string
		Scores []int32
	}

	// Create an instance of TestStruct
	testData := TestStruct{
		Age:    25,
		Weight: 72.5,
		Active: true,
		Name:   "John Doe",
		Scores: []int32{90, 85, 88},
	}

	// Expected byte slice after encoding testData
	buf := &bytes.Buffer{}

	// Manually encode testData to match the expected output of Serializer
	binary.Write(buf, binary.BigEndian, testData.Age)
	binary.Write(buf, binary.BigEndian, testData.Weight)
	binary.Write(buf, binary.BigEndian, testData.Active)

	// Encode the Name field with its length
	nameBytes := []byte(testData.Name)
	binary.Write(buf, binary.BigEndian, int32(len(nameBytes)))
	buf.Write(nameBytes)

	// Encode the Scores slice with its length
	binary.Write(buf, binary.BigEndian, int32(len(testData.Scores)))
	for _, score := range testData.Scores {
		binary.Write(buf, binary.BigEndian, score)
	}

	// Encode testData using Serializer
	encodedBytes, err := srmcp.Serializer(testData)
	if err != nil {
		t.Errorf("Serializer returned an error: %v", err)
	}

	// Compare the encoded bytes with the expected bytes
	if !reflect.DeepEqual(encodedBytes, buf.Bytes()) {
		t.Errorf("Encoded bytes do not match expected bytes.\nGot: %v\nExpected: %v", encodedBytes, buf.Bytes())
	}

	t.Logf("Encoded bytes: %v", encodedBytes)
}

// TestSerializationDeserialization tests the Serializer and Deserializer functions.
func TestSerializationDeserialization(t *testing.T) {

	// TestStruct is a struct for testing serialization and deserialization.
	type TestStruct struct {
		Age    uint32
		Name   string
		Scores []int32
	}
	original := TestStruct{
		Age:    30,
		Name:   "Alice",
		Scores: []int32{100, 95, 80},
	}

	// Serialize the original struct
	serialized, err := srmcp.Serializer(original)
	if err != nil {
		t.Fatalf("Failed to serialize: %v", err)
	}

	// Deserialize into a new struct
	var deserialized TestStruct
	err = srmcp.Deserializer(serialized, &deserialized)
	if err != nil {
		t.Fatalf("Failed to deserialize: %v", err)
	}

	// Compare the original and deserialized structs
	if !reflect.DeepEqual(original, deserialized) {
		t.Errorf("Original and deserialized structs do not match.\nOriginal: %+v\nDeserialized: %+v", original, deserialized)
	}

	t.Logf("Original: %+v", original)
	t.Logf("Deserialized: %+v", deserialized)
}
