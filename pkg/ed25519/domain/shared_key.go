package domain

import (
	"crypto/sha512"
	"encoding/hex"
	"strings"
)

const SignLength = 6

type SharedKey []byte

func (shared SharedKey) Sign() (sign string, err error) {
	hashFn := sha512.New()
	hashFn.Write(shared)
	hash := hashFn.Sum(nil)
	hashStr := hex.EncodeToString(hash)

	hashLen := len(hashStr)
	if hashLen < SignLength {
		diff := SignLength - hashLen
		padding := strings.Repeat("0", diff)

		sign = padding + hashStr
	} else {
		sign = hashStr[0:SignLength]
	}

	return sign, nil
}
