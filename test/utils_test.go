package test

import (
	"github.com/ulfaric/srmcp"
	"reflect"
	"testing"
	"time"
)


// TestSerialization tests the Serializer and Deserializer functions.
func TestSerialization(t *testing.T) {
    // DeepNestedStruct is a struct to be nested within NestedStruct.
    type DeepNestedStruct struct {
        ID      uint32
        Details string
    }

    // NestedStruct is updated to include a slice of DeepNestedStruct.
    type NestedStruct struct {
        ID       uint32
        Info     string
        DeepInfo []DeepNestedStruct // New field for deeper nesting
    }

    // TestStruct definition remains the same, but will now include deeper nested slices.
    type TestStruct struct {
        Age      uint32
        Name     string
        Scores   []int32
        Birthday time.Time
        Details  NestedStruct
        MoreInfo []NestedStruct
    }

    original := TestStruct{
        Age:      30,
        Name:     "Alice",
        Scores:   []int32{100, 95, 80},
        Birthday: time.Now(),
        Details: NestedStruct{
            ID:   1,
            Info: "Additional details",
            DeepInfo: []DeepNestedStruct{ // Adding deep nested elements
                {ID: 1, Details: "Deep info 1"},
            },
        },
        MoreInfo: []NestedStruct{
            {
                ID:   2,
                Info: "More info 1",
                DeepInfo: []DeepNestedStruct{ // Adding deep nested elements
                    {ID: 2, Details: "Deep info 2"},
                },
            },
            {
                ID:   3,
                Info: "More info 2",
                DeepInfo: []DeepNestedStruct{ // Adding deep nested elements
                    {ID: 3, Details: "Deep info 3"},
                },
            },
        },
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

    t.Logf("Original struct: %+v", original)
    t.Logf("Deserialized struct: %+v", deserialized)
}