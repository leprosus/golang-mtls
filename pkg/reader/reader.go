package reader

import (
	"io"

	"mtls/pkg/cipher"
)

type Reader struct {
	origin io.Reader
	cipher *cipher.Cipher
}

func NewReader(origin io.Reader, cipher *cipher.Cipher) (reader *Reader) {
	return &Reader{
		origin: origin,
		cipher: cipher,
	}
}

func (r *Reader) Read(dst []byte) (num int, err error) {
	var bs []byte

	bs, err = io.ReadAll(r.origin)
	if err != nil {
		return num, err
	}

	bs, err = r.cipher.Encode(bs)
	if err != nil {
		return num, err
	}

	num = copy(dst, bs)

	return num, io.EOF
}
