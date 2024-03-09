package cipher

import (
	"testing"

	"mtls/pkg/curve25519"
	"mtls/pkg/ed25519"
)

func provideCipher() (cipher *Cipher, err error) {
	pub, priv, err := ed25519.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	var shared []byte
	shared, err = curve25519.GenerateSharedKey(pub, priv)
	if err != nil {
		return nil, err
	}

	cipher, err = NewCipher(shared)
	if err != nil {
		return nil, err
	}

	return cipher, nil
}

func TestCipher(t *testing.T) {
	cipher, err := provideCipher()
	if err != nil {
		t.Fatal(err.Error())
	}

	origin := []byte("a special secret message")

	var encoded []byte
	encoded, err = cipher.Encode(origin)
	if err != nil {
		t.Fatal(err.Error())
	}

	var decoded []byte
	decoded, err = cipher.Decode(encoded)
	if err != nil {
		t.Fatal(err.Error())
	}

	if string(origin) != string(decoded) {
		t.Fatal("Origin and Decoded are not equal")
	}
}

func BenchmarkCipherEncode(b *testing.B) {
	cipher, err := provideCipher()
	if err != nil {
		b.Fatal(err.Error())
	}

	origin := []byte("a special secret message")

	for i := 0; i < b.N; i++ {
		_, err = cipher.Encode(origin)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}

func BenchmarkCipherDecode(b *testing.B) {
	origin := []byte("a special secret message")

	cipher, err := provideCipher()
	if err != nil {
		b.Fatal(err.Error())
	}

	var encoded []byte
	encoded, err = cipher.Encode(origin)
	if err != nil {
		b.Fatal(err.Error())
	}

	for i := 0; i < b.N; i++ {
		_, err = cipher.Decode(encoded)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}
