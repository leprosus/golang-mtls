package native_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"mtls/middleware"
	"mtls/middleware/native"
	"mtls/mtls"
	"mtls/pkg/ed25519"
)

type nullMux struct{}

func (n nullMux) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	data, err := io.ReadAll(req.Body)
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)

		return
	}

	_, err = res.Write(data)
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)

		return
	}
}

func initMTLS(t *testing.T) (aliceMTLS, bobMTLS *mtls.MTLS) {
	t.Helper()

	alicePub, alicePriv, err := ed25519.GeneratePemBytesPair()
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := ed25519.GeneratePemBytesPair()
	if err != nil {
		t.Fatal(err)
	}

	aliceMTLS, err = mtls.NewMTLS(bobPub, alicePriv)
	if err != nil {
		t.Fatal(err)
	}

	bobMTLS, err = mtls.NewMTLS(alicePub, bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	return aliceMTLS, bobMTLS
}

func TestMTLS(t *testing.T) {
	t.Parallel()

	var aliceMTLS, bobMTLS *mtls.MTLS
	aliceMTLS, bobMTLS = initMTLS(t)

	const original = "test text"

	encoded, err := bobMTLS.Encode([]byte(original))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encoded))
	req.Header.Add(middleware.MTLSSignHeader, bobMTLS.Sign())

	rec := httptest.NewRecorder()

	mux := &nullMux{}
	log := slog.Default()

	testMiddleware := native.NewMTLS(mux, log, aliceMTLS)
	testMiddleware.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the main handler returns %v status", res.Status)
	}

	var bs []byte

	bs, err = io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		_ = res.Body.Close()
	}()

	if original != string(bs) {
		t.Fatal("middleware works unwell")
	}
}
