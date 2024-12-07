package request

import (
	"context"
	"io"
	"net/http"

	"github.com/leprosus/golang-crypto/reader"
	"github.com/leprosus/golang-mtls/middleware"
	"github.com/leprosus/golang-mtls/mtls"
)

func NewRequest(method, url string, body io.Reader, mtls *mtls.MTLS) (req *http.Request, err error) {
	return NewRequestWithContext(context.Background(), method, url, body, mtls)
}

func NewRequestWithContext(ctx context.Context, method, url string,
	body io.Reader, mtls *mtls.MTLS,
) (req *http.Request, err error) {
	req, err = http.NewRequestWithContext(ctx, method, url, reader.NewReader(body, mtls.Cipher()))
	if err != nil {
		return req, err
	}

	sign := mtls.Sign()
	req.Header.Add(middleware.MTLSSignHeader, sign)

	return
}
