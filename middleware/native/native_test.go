package native

import (
	"bytes"
	"io"
	"log/slog"
	. "mtls/middleware"
	"mtls/mtls"
	"mtls/pkg/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
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

func TestMTLS(t *testing.T) {
	alicePub, alicePriv, err := ed25519.GeneratePemBytesPair()
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := ed25519.GeneratePemBytesPair()
	if err != nil {
		t.Fatal(err)
	}

	var aliceMTLS *mtls.MTLS
	aliceMTLS, err = mtls.NewMTLS(bobPub, alicePriv)
	if err != nil {
		t.Fatal(err)
	}

	var bobMTLS *mtls.MTLS
	bobMTLS, err = mtls.NewMTLS(alicePub, bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	const original = "test text"

	var encoded []byte
	encoded, err = bobMTLS.Encode([]byte(original))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encoded))
	req.Header.Add(MTLSSignHeader, bobMTLS.Sign())

	rec := httptest.NewRecorder()

	mux := &nullMux{}
	log := slog.Default()

	middleware := NewMTLS(mux, log, aliceMTLS)
	middleware.ServeHTTP(rec, req)

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
