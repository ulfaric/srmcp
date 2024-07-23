package messages

type HandShake struct {
	PublicKey []byte `validate:"required"`
}

type HandShakeResponse struct {
	CipherText []byte `validate:"required"`
}