package client

type Transaction struct {
	ID        string
	Completed chan bool
	Error     string
}
