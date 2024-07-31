package messages

type Read struct {
	NodeIDs   []string `validate:"required"`
	NodeNames []string `validate:"required"`
}

type ReadResponse struct {
	NodeID   string      `validate:"required"`
	NodeName string      `validate:"required"`
	Value    interface{} `validate:"required"`
}
