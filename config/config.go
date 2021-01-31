package config

import (
	"flag"
	"fmt"
	_ "fmt"
	"os"
	"sync"
)

// Configuration for the tproxy
type Configuration struct {
	HTTPPort  int
	HTTPSPort int
	APIPort   int
	SSLKey    string
	SSLCert   string
}

var config Configuration
var configError error
var onlyOnce sync.Once

// ParseArgs parse the command line args
func ParseArgs() (*Configuration, error) {
	onlyOnce.Do(func() {
		flag.StringVar(&config.SSLKey, "sslKey", "/ca/tls.key", "the tls key file")
		flag.StringVar(&config.SSLCert, "sslCert", "/ca/tls.crt", "the tls cert file")
		flag.IntVar(&config.HTTPPort, "httpPort", 8080, "the HTTP listen port")
		flag.IntVar(&config.HTTPSPort, "httpsPort", 8443, "the HTTPS listen port")
		flag.IntVar(&config.APIPort, "apiPort", 7070, "the API and metric listen port")
		flag.Parse()

		if _, err := os.Stat(config.SSLKey); os.IsNotExist(err) {
			configError := fmt.Errorf("sslKey not found: %s", config.SSLKey)
			_ = configError
		}
		if _, err := os.Stat(config.SSLCert); os.IsNotExist(err) {
			configError := fmt.Errorf("sslCert not found: %s", config.SSLCert)
			_ = configError
		}
	})
	if configError != nil {
		return nil, configError
	}
	return &config, nil
}
