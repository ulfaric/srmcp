package srmcp

type Node struct {
	ID string
	Type string
	Value interface{}
	Parent []*Node
	Children []*Node
}
