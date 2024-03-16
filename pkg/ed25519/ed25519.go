package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

var ErrImpossibleToParseBytesToEd25519 = errors.New("impossible to parse bytes to Ed25519 public key")

func GenerateKeyPair() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

func ConvKeyPairToBytesPair(pub ed25519.PublicKey, priv ed25519.PrivateKey) (pubBs, privBs []byte, err error) {
	pubBs, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	privBs, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	return pubBs, privBs, err
}

func GenerateBytesPair() (pubBs, privBs []byte, err error) {
	var (
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	)

	pub, priv, err = GenerateKeyPair()
	if err != nil {
		return pubBs, privBs, err
	}

	return ConvKeyPairToBytesPair(pub, priv)
}

func ConvKeyPairToPemBlocks(pub ed25519.PublicKey, priv ed25519.PrivateKey) (pubPem, privPem pem.Block) {
	pubPem = pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pub,
	}

	privPem = pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priv,
	}

	return pubPem, privPem
}

func GeneratePemBlockPair() (pubPem, privPem pem.Block, err error) {
	var (
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	)

	pub, priv, err = GenerateBytesPair()
	if err != nil {
		return pubPem, privPem, err
	}

	pubPem, privPem = ConvKeyPairToPemBlocks(pub, priv)

	return pubPem, privPem, nil
}

func GeneratePemBytesPair() (pubBs, privBs []byte, err error) {
	var (
		pubPem  pem.Block
		privPem pem.Block
	)

	pubPem, privPem, err = GeneratePemBlockPair()
	if err != nil {
		return nil, nil, err
	}

	pubBs = pem.EncodeToMemory(&pubPem)

	privBs = pem.EncodeToMemory(&privPem)

	return pubBs, privBs, nil
}

func GeneratePemFiles(dirPath, baseName string) (err error) {
	dirPath, err = filepath.Abs(dirPath)
	if err != nil {
		return err
	}

	fileName := filepath.Join(dirPath, baseName)

	var (
		pubBs,
		privBs []byte
	)

	pubBs, privBs, err = GeneratePemBytesPair()
	if err != nil {
		return err
	}

	const pubPerm = 0o644

	err = os.WriteFile(fileName+".pub", pubBs, pubPerm)
	if err != nil {
		return err
	}

	const privPerm = 0o600

	err = os.WriteFile(fileName, privBs, privPerm)
	if err != nil {
		return err
	}

	return nil
}

func ParsePemBlockPair(pubPem, privPem pem.Block) (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	var parsed any

	parsed, err = x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		return nil, nil, err
	}

	var ok bool

	pub, ok = parsed.(ed25519.PublicKey)
	if !ok {
		return nil, nil, ErrImpossibleToParseBytesToEd25519
	}

	parsed, err = x509.ParsePKCS8PrivateKey(privPem.Bytes)
	if err != nil {
		return nil, nil, err
	}

	priv, ok = parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, ErrImpossibleToParseBytesToEd25519
	}

	return pub, priv, err
}

func ParsePemBytesPair(pubBs, privBs []byte) (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	pubPem, _ := pem.Decode(pubBs)
	privPem, _ := pem.Decode(privBs)

	return ParsePemBlockPair(*pubPem, *privPem)
}

func ParseBytesPair(pubBs, privBs []byte) (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	pubPem, privPem := ConvKeyPairToPemBlocks(pubBs, privBs)

	return ParsePemBlockPair(pubPem, privPem)
}
