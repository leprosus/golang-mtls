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
	"mtls/pkg/ed25519/domain"
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

	alicePub, alicePriv, err := ed25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var alicePubPEM domain.PEMBlock

	alicePubPEM, err = alicePub.ToPEMBlock()
	if err != nil {
		t.Fatal(err)
	}

	var alicePrivPEM domain.PEMBlock

	alicePrivPEM, err = alicePriv.ToPEMBlock()
	if err != nil {
		t.Fatal(err)
	}

	bobPub, bobPriv, err := ed25519.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var bobPubPEM domain.PEMBlock

	bobPubPEM, err = bobPub.ToPEMBlock()
	if err != nil {
		t.Fatal(err)
	}

	var bobPrivPEM domain.PEMBlock

	bobPrivPEM, err = bobPriv.ToPEMBlock()
	if err != nil {
		t.Fatal(err)
	}

	aliceMTLS, err = mtls.NewMTLS(bobPubPEM.ToBytes(), alicePrivPEM.ToBytes())
	if err != nil {
		t.Fatal(err)
	}

	bobMTLS, err = mtls.NewMTLS(alicePubPEM.ToBytes(), bobPrivPEM.ToBytes())
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

	var decoded []byte

	decoded, err = aliceMTLS.Decode(bs)
	if err != nil {
		t.Fatal(err)
	}

	if original != string(decoded) {
		t.Fatal("middleware works unwell")
	}

	mtlsHeader := res.Header.Get(middleware.MTLSSignHeader)
	if mtlsHeader == "" {
		t.Fatalf("response doesn't contain %s header", middleware.MTLSSignHeader)
	}

	if mtlsHeader != bobMTLS.Sign() {
		t.Fatalf("response contains %s headerthat are not equal to received", middleware.MTLSSignHeader)
	}
}
