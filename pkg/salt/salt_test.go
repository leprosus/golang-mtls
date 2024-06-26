package salt_test

import (
	"testing"

	"github.com/leprosus/golang-mtls/pkg/salt"
)

func TestGenerateSalt(t *testing.T) {
	t.Parallel()

	const length = 8

	salt, err := salt.GenerateSalt(length)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(salt) != length {
		t.Fatal("GenerateSalt returns a unexpected length salt")
	}
}
