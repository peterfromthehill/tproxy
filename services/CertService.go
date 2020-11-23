package services

import (
	"crypto/rsa"
	"crypto/x509"
	"log"
)

var caCer *x509.Certificate
var caKey *rsa.PrivateKey

type CertService struct {
	SslCertFile string
	SslKeyFile  string
}

func (this CertService) Bootstrap() {
	var err error
	caCer, caKey, err = bootstrap(this.SslCertFile, this.SslKeyFile)
	if err != nil {
		log.Println(err)
		return
	}
}

func bootstrap(tlsCertPath, privateKeyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certLoader := CertLoader{tlsCertPath}
	cer, err := certLoader.loadX509fromFile()
	if err != nil {
		return nil, nil, err
	}

	privateKeyLoader := PrivateKeyLoader{privateKeyPath}
	key, err := privateKeyLoader.loadPKfromFile()
	if err != nil {
		return nil, nil, err
	}

	cacheService := CacheService{}
	cacheService.makeAndWatch()
	return cer, key, nil
}
