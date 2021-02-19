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
	cacheService := services.Init()
	cacheService.Watch()

	certService := &services.CertService{
		SslCertFile:  xconfig.SSLCert,
		SslKeyFile:   xconfig.SSLKey,
		CacheService: cacheService,
	}
	certService.Bootstrap()

	api := &webserver.API{
		Port:        xconfig.APIPort,
		CertService: *certService,
	}
	go api.StartAPIServer()

	server := &webserver.Webserver{
		HttpPort:    xconfig.HTTPPort,
		HttpsPort:   xconfig.HTTPSPort,
		SSLCert:     xconfig.SSLCert,
		SSLKey:      xconfig.SSLKey,
		CertService: certService,
	}
	server.StartWebserver()
}
