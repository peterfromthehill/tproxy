package main

import (
	"github.com/peterfromthehill/tproxy/config"
	"github.com/peterfromthehill/tproxy/services"
	"github.com/peterfromthehill/tproxy/webserver"
	"log"
	"os"
)

func main() {
	e := config.Envs{}
	e.VerifyEnvs()

	log.SetFlags(log.Lshortfile)
	certService := services.CertService{os.Getenv(config.SSLCERT_FILE), os.Getenv(config.SSLKEY_FILE)}
	certService.Bootstrap()

	server := webserver.Webserver{os.Getenv(config.HTTP_PORT), os.Getenv(config.HTTPS_PORT)}
	server.StartWebserver()
}
