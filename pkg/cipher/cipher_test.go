package cipher_test

import (
	"testing"

	"github.com/leprosus/golang-mtls/pkg/ed25519/domain"

	"github.com/leprosus/golang-mtls/pkg/cipher"
	"github.com/leprosus/golang-mtls/pkg/ed25519"
)

func provideCipher() (c *cipher.Cipher, err error) {
	var (
		pub  domain.PublicKey
		priv domain.PrivateKey
	)

	pub, priv, err = ed25519.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	var shared domain.SharedKey

	shared, err = ed25519.GenerateSharedKey(pub, priv)
	if err != nil {
		return nil, err
	}

	c, err = cipher.NewCipher(shared)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func TestCipher(t *testing.T) {
	t.Parallel()

	testCipher, err := provideCipher()
	if err != nil {
		t.Fatal(err.Error())
	}

	origin := []byte("a special secret message")

	var encoded []byte

	encoded, err = testCipher.Encode(origin)
	if err != nil {
		t.Fatal(err.Error())
	}

	var decoded []byte

	decoded, err = testCipher.Decode(encoded)
	if err != nil {
		t.Fatal(err.Error())
	}

	if string(origin) != string(decoded) {
		t.Fatal("Origin and Decoded are not equal")
	}
}

func BenchmarkCipherEncode(b *testing.B) {
	testCipher, err := provideCipher()
	if err != nil {
		b.Fatal(err.Error())
	}

	origin := []byte("a special secret message")

	for range b.N {
		_, err = testCipher.Encode(origin)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}

func BenchmarkCipherDecode(b *testing.B) {
	origin := []byte("a special secret message")

	testCipher, err := provideCipher()
	if err != nil {
		b.Fatal(err.Error())
	}

	var encoded []byte

	encoded, err = testCipher.Encode(origin)
	if err != nil {
		b.Fatal(err.Error())
	}

	for range b.N {
		_, err = testCipher.Decode(encoded)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}
