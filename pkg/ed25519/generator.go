package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
)

func GenerateKeyPair() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	return ed25519.GenerateKey(rand.Reader)
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

	pubBs, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return pubBs, privBs, err
	}

	privBs, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return pubBs, privBs, err
	}

	return pubBs, privBs, nil
}

func GeneratePemBlocks() (pubPem, privPem pem.Block, err error) {
	var (
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	)

	pub, priv, err = GenerateBytesPair()
	if err != nil {
		return pubPem, privPem, err
	}

	pubPem = pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pub,
	}

	privPem = pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priv,
	}

	return pubPem, privPem, nil
}

func GeneratePemFiles(dirPath, baseName string) (err error) {
	var (
		pubPem  pem.Block
		privPem pem.Block
	)
	pubPem, privPem, err = GeneratePemBlocks()
	if err != nil {
		return err
	}

	dirPath, err = filepath.Abs(dirPath)
	if err != nil {
		return err
	}

	fileName := filepath.Join(dirPath, baseName)

	err = os.WriteFile(fileName+".pub", pem.EncodeToMemory(&pubPem), 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(fileName, pem.EncodeToMemory(&privPem), 0600)
	if err != nil {
		return err
	}

	return nil
}
