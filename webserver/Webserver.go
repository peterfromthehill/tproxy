package webserver

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/peterfromthehill/tproxy/services"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmhttp"
)

type Webserver struct {
	HttpPort, HttpsPort string
}

func (this Webserver) StartWebserver() {
	const NETWORK = "tcp"

	config := &tls.Config{
		GetCertificate: services.ReturnCert,
	}

	finish := make(chan bool)

	httpsListener, err := tls.Listen(NETWORK, ":"+this.HttpsPort, config)
	if err != nil {
		log.Println(err)
		return
	}
	defer httpsListener.Close()

	httpListener, err := net.Listen(NETWORK, ":"+this.HttpPort)
	if err != nil {
		log.Println(err)
		return
	}

	this.serve(httpsListener, "https")
	this.serve(httpListener, "http")
	log.Printf("Webserver startd in Ports %s & %s", this.HttpPort, this.HttpsPort)
	<-finish
}

func (this Webserver) serve(listener net.Listener, scheme string) {
	go func() {
		err := http.Serve(listener, apmhttp.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			span, ctx := apm.StartSpan(r.Context(), "HandlerFunc", "request")
			defer span.End()

			requestHandler := services.RequestHandler{w, r, scheme}
			requestHandler.HandleHTTP(ctx)
		})))
		fmt.Errorf(scheme+": %s", err)
	}()
}
