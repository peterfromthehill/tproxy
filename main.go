package main

import (
	"log"

	"github.com/peterfromthehill/tproxy/config"
	"github.com/peterfromthehill/tproxy/services"
	"github.com/peterfromthehill/tproxy/webserver"
)

func main() {
	xconfig, err := config.ParseArgs()
	if err != nil {
		log.Fatal(err)
	}

	log.SetFlags(log.Lshortfile | log.LstdFlags)

	certService := services.CertService{xconfig.SSLCert, xconfig.SSLKey}
	certService.Bootstrap()

	api := webserver.API{xconfig.APIPort}
	go api.StartAPIServer()

	server := webserver.Webserver{xconfig.HTTPPort, xconfig.HTTPSPort, xconfig.SSLCert, xconfig.SSLKey}
	server.StartWebserver()
}
