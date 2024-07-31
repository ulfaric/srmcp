package messages

type Write struct {
	NodeID   string      `validate:"required"`
	NodeName string      `validate:"required"`
	Value	interface{} `validate:"required"`
}

type WriteResponse struct {
	NodeID   string      `validate:"required"`
	NodeName string      `validate:"required"`
	Value    interface{} `validate:"required"`
}