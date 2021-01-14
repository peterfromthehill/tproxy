package main

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/peterfromthehill/tproxy/services"
)

func TestCopyHeader(t *testing.T) {
	var src = http.Header{}
	var dst = http.Header{}
	src.Add("host", "localhost")
	src.Add("Connection", "keep-alive")
	src.Add("Keep-alive", "10")

	var assertdst = http.Header{}
	assertdst.Add("host", "localhost")
	assertdst.Add("Connection", "close")

	services.CopyHeader(dst, src)

	if !reflect.DeepEqual(dst, assertdst) {
		t.Errorf("dst not equal assertdst: %s <=> %s", dst, assertdst)
	}
}
