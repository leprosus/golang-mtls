package reader_test

import (
	"io"
	"strings"
	"testing"

	"mtls/pkg/cipher"
	"mtls/pkg/ed25519/domain"
	"mtls/pkg/reader"
)

//nolint:gochecknoglobals
var (
	sharedBs = []byte{
		189, 114, 85, 127, 150, 168, 2, 76, 197, 132, 223, 148, 211, 159, 11, 116, 229, 183, 108, 37,
		115, 90, 159, 238, 121, 103, 82, 33, 19, 117, 103, 114,
	}
	shared = domain.SharedKey(sharedBs)
)

func TestReader_Read(t *testing.T) {
	t.Parallel()

	testCipher, err := cipher.NewCipher(shared)
	if err != nil {
		t.Fatal(err)
	}

	const original = "some text for test"

	testReader := reader.NewReader(strings.NewReader(original), testCipher)

	var read []byte

	read, err = io.ReadAll(testReader)
	if err != nil {
		t.Fatal(err)
	}

	var decoded []byte

	decoded, err = testCipher.Decode(read)
	if err != nil {
		t.Fatal(err)
	}

	if original != string(decoded) {
		t.Fatal("encoded by the cipher and got from the reader are not equal")
	}
}
