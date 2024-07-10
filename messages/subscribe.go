package messages

import (
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/node"
)

// Subscribe message
type Subscribe struct {
	Header   Header
	Topic    string
	Node     []*node.Node
	Interval interface{}
	Duration interface{}
}

// Subscribe message constructor
func NewSubscribe(SenderID string, topic string, nodes []*node.Node, interval interface{}, duration interface{}) *Subscribe {
	return &Subscribe{
		Header: Header{
			MessageType: srmcp.Subscribe,
			SenderID:    SenderID,
		},
		Topic:    topic,
		Node:     nodes,
		Interval: interval,
		Duration: duration,
	}
}

// Get the header of the message
func (subscribe *Subscribe) GetHeader() Header {
	return subscribe.Header
}

// Get the topic of the message
func (subscribe *Subscribe) GetTopic() string {
	return subscribe.Topic
}

// Get the nodes in the message
func (subscribe *Subscribe) GetNodes() []*node.Node {
	return subscribe.Node
}

// Get the interval of the message
func (subscribe *Subscribe) GetInterval() interface{} {
	return subscribe.Interval
}

// Get the duration of the message
func (subscribe *Subscribe) GetDuration() interface{} {
	return subscribe.Duration
}

// Set the topic of the message
func (subscribe *Subscribe) SetTopic(topic string) {
	subscribe.Topic = topic
}

// Set the nodes in the message
func (subscribe *Subscribe) SetNodes(nodes []*node.Node) {
	subscribe.Node = nodes
}

// Set the interval of the message
func (subscribe *Subscribe) SetInterval(interval interface{}) {
	subscribe.Interval = interval
}

// Set the duration of the message
func (subscribe *Subscribe) SetDuration(duration interface{}) {
	subscribe.Duration = duration
}