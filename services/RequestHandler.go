package services

import (
	"io"
	"log"
	"net/http"
	"strings"
)

type RequestHandler struct {
	Writer http.ResponseWriter
	Req    *http.Request
	Scheme string
}

func (this RequestHandler) HandleHTTP() {
	var requestHeader = http.Header{}
	CopyHeader(requestHeader, this.Req.Header)

	this.Req.URL.Scheme = this.Scheme
	this.Req.URL.Host = this.Req.Host

	log.Printf("%s => %s %s", this.Req.RemoteAddr, this.Req.Method, this.Req.URL)

	resp, err := http.DefaultTransport.RoundTrip(this.Req)
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
