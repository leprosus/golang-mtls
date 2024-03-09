package salt

import (
	"crypto/rand"
	"io"
)

type Salt []byte

func GenerateSalt(saltSize int) (s Salt, err error) {
	s = make([]byte, saltSize)
	_, err = io.ReadFull(rand.Reader, s)

	return s, err
}
