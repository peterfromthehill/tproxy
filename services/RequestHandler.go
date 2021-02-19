package services

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"

	"go.elastic.co/apm/module/apmhttp"
)

type RequestHandler struct {
	Writer http.ResponseWriter
	Req    *http.Request
	Scheme string
}

func (this RequestHandler) HandleHTTP(ctx context.Context) {
	this.Req.URL.Scheme = this.Scheme
	this.Req.URL.Host = this.Req.Host
	log.Printf("%s => %s %s", this.Req.RemoteAddr, this.Req.Method, this.Req.URL)
	roundTripper := apmhttp.WrapRoundTripper(http.DefaultTransport)
	resp, err := roundTripper.RoundTrip(this.Req)
	if err != nil {
		http.Error(this.Writer, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	log.Printf("%s <= %s %d", this.Req.RemoteAddr, resp.Status, resp.ContentLength)
	CopyHeader(this.Writer.Header(), resp.Header)
	this.Writer.WriteHeader(resp.StatusCode)
	io.Copy(this.Writer, resp.Body)
}

func CopyHeader(dst, src http.Header) {
	for k, vv := range src {
		if strings.ToLower(k) == "connection" {
			dst.Add(k, "close")
		} else if strings.ToLower(k) == "keep-alive" {
			continue
		} else {
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
	}
}
