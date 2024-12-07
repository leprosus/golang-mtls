package native

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"

	"github.com/leprosus/golang-crypto/ed25519/domain"
	"github.com/leprosus/golang-mtls/middleware"
	"github.com/leprosus/golang-mtls/mtls"
)

type MTLS struct {
	mux  http.Handler
	log  *slog.Logger
	mtls *mtls.MTLS

	config
}

type config struct {
	bodySizeLimit uint64
}

const (
	kilo = 1024
	mega = kilo * kilo

	DefaultBodySizeLimit = mega
)

func NewMTLS(mux http.Handler, log *slog.Logger, mtls *mtls.MTLS) (middleware *MTLS) {
	return &MTLS{
		mux:  mux,
		log:  log,
		mtls: mtls,

		config: config{
			bodySizeLimit: DefaultBodySizeLimit,
		},
	}
}

func (m *MTLS) SetBodySizeLimit(size uint64) {
	m.bodySizeLimit = size
}

func (m *MTLS) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	sign := req.Header.Get(middleware.MTLSSignHeader)
	signLen := len(sign)

	if signLen == 0 {
		return
	}

	log := m.log.With(
		slog.String("method", req.Method),
		slog.String("path", req.RequestURI))

	isValidSign := signLen == domain.SignLength && sign == m.mtls.Sign()
	if !isValidSign {
		res.WriteHeader(http.StatusUnauthorized)

		log.Warn("got an unsupported MTLS sign",
			slog.String("received_sign", sign),
			slog.String("expected_sign", m.mtls.Sign()))

		return
	}

	reader := io.LimitReader(req.Body, int64(m.bodySizeLimit))

	bs, err := io.ReadAll(reader)
	if err != nil {
		res.WriteHeader(http.StatusRequestEntityTooLarge)

		log.Error("got a request entity is larger than the limit",
			slog.String("error", err.Error()))

		return
	}

	var decoded []byte

	decoded, err = m.mtls.Decode(bs)
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)

		log.Error("got a undecoded request",
			slog.String("error", err.Error()))

		return
	}

	log.Debug("the request was decrypted successfully")

	req.Body = io.NopCloser(bytes.NewReader(decoded))
	req.ContentLength = int64(len(decoded))

	rw := newResponseWriter(m.mtls, res, log)

	m.mux.ServeHTTP(rw, req)
}
