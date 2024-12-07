package request_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leprosus/golang-crypto/cipher"
	"github.com/leprosus/golang-crypto/ed25519/domain"
	"github.com/leprosus/golang-mtls/mtls"
	"github.com/leprosus/golang-mtls/request"
)

//nolint:gochecknoglobals
var (
	sharedBs = []byte{
		189, 114, 85, 127, 150, 168, 2, 76, 197, 132, 223, 148, 211, 159, 11, 116, 229, 183, 108, 37,
		115, 90, 159, 238, 121, 103, 82, 33, 19, 117, 103, 114,
	}
	shared = domain.SharedKey(sharedBs)
)

func TestNewRequest(t *testing.T) {
	t.Parallel()

	testCipher, err := cipher.NewCipher(shared)
	if err != nil {
		t.Fatal(err)
	}

	var testMTLS *mtls.MTLS

	testMTLS, err = mtls.NewMTLSWithSharedKey(shared)
	if err != nil {
		t.Fatal(err)
	}

	const body = `{"value": "key"}`

	var req *http.Request

	req, err = request.NewRequest(http.MethodPost, "/", strings.NewReader(body), testMTLS)
	if err != nil {
		t.Fatal(err)
	}

	var bs []byte

	bs, err = io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err.Error())
	}

	var decoded []byte

	decoded, err = testCipher.Decode(bs)
	if err != nil {
		t.Fatal(err.Error())
	}

	if body != string(decoded) {
		t.Fatal("the decoded body and the original body are not equal")
	}
}
