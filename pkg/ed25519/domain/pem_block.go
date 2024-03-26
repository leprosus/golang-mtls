package domain

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrIncorrectPEMType                = errors.New("incorrect PEM type")
	ErrImpossibleToParseBytesToEd25519 = errors.New("impossible to parse bytes to Ed25519 public key")
	ErrBadPEMBytes                     = errors.New("can not load PEM block from bytes")
)

type PEMBlock pem.Block

func (pb *PEMBlock) ToPublicKey() (pub PublicKey, err error) {
	if strings.ToUpper(pb.Type) != publicKeyPEMType {
		return pub, ErrIncorrectPEMType
	}

	var parsed any

	parsed, err = x509.ParsePKIXPublicKey(pb.Bytes)
	if err != nil {
		return pub, err
	}

	edPub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return pub, ErrImpossibleToParseBytesToEd25519
	}

	pub = PublicKey(edPub)

	return pub, nil
}

func (pb *PEMBlock) ToPrivateKey() (priv PrivateKey, err error) {
	if strings.ToUpper(pb.Type) != privateKeyPEMType {
		return priv, ErrIncorrectPEMType
	}

	var parsed any

	parsed, err = x509.ParsePKCS8PrivateKey(pb.Bytes)
	if err != nil {
		return priv, err
	}

	edPriv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return priv, ErrImpossibleToParseBytesToEd25519
	}

	priv = PrivateKey(edPriv)

	return priv, nil
}

func (pb *PEMBlock) ToBytes() (bs []byte) {
	block := pem.Block(*pb)

	return pem.EncodeToMemory(&block)
}

func (pb *PEMBlock) Save(filePath string) (err error) {
	filePath, err = filepath.Abs(filePath)
	if err != nil {
		return err
	}

	var perm os.FileMode

	switch strings.ToUpper(pb.Type) {
	case publicKeyPEMType:
		perm = publicPerm
	case privateKeyPEMType:
		perm = privatePerm
	}

	err = os.WriteFile(filePath, pb.ToBytes(), perm)
	if err != nil {
		return err
	}

	return nil
}

func (pb *PEMBlock) FromBytes(bs []byte) (err error) {
	block, _ := pem.Decode(bs)

	if block == nil {
		return ErrBadPEMBytes
	}

	pemBlock := PEMBlock(*block)

	*pb = pemBlock

	return nil
}
