package webserver

import (
	"crypto/tls"
	"fmt"
	"github.com/peterfromthehill/tproxy/services"
	"log"
	"net"
	"net/http"
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

	<-finish
}

func (this Webserver) serve(listener net.Listener, scheme string) {
	go func() {
		err := http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestHandler := services.RequestHandler{w, r, scheme}
			requestHandler.HandleHTTP()
		}))
		fmt.Errorf(scheme+": %s", err)
	}()
}
