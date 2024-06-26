package native

import (
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/leprosus/golang-mtls/middleware"
	"github.com/leprosus/golang-mtls/mtls"
)

var ErrDataHasBeenWritten = errors.New("data has been written")

type responseWriter struct {
	mtls   *mtls.MTLS
	origin http.ResponseWriter
	log    *slog.Logger

	hasWrittenData atomic.Bool
}

func newResponseWriter(core *mtls.MTLS, rw http.ResponseWriter, log *slog.Logger) *responseWriter {
	return &responseWriter{
		mtls:   core,
		origin: rw,
		log:    log,
	}
}

func (rw *responseWriter) Header() (header http.Header) {
	return rw.origin.Header()
}

func (rw *responseWriter) Write(bs []byte) (num int, err error) {
	if rw.hasWrittenData.Load() {
		rw.log.Error(ErrDataHasBeenWritten.Error())

		return num, ErrDataHasBeenWritten
	}

	rw.Header().Add(middleware.MTLSSignHeader, rw.mtls.Sign())

	var decoded []byte

	decoded, err = rw.mtls.Encode(bs)
	if err != nil {
		rw.log.Error(err.Error())

		return num, err
	}

	num, err = rw.origin.Write(decoded)
	if err != nil {
		rw.log.Error(err.Error())

		return num, err
	}

	rw.hasWrittenData.Store(true)

	return num, nil
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.origin.WriteHeader(statusCode)
}
