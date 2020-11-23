package services

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

type CertLoader struct {
	file string
}

func (this CertLoader) loadX509fromFile() (*x509.Certificate, error) {
	cert, err := ioutil.ReadFile(this.file)
	if err != nil {
		return nil, err
	}
	cer, err := parseX509Cert(cert)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", this.file, err)
	}
	return cer, nil
}

func parseX509Cert(cert []byte) (*x509.Certificate, error) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(cert)
	if !ok {
		return nil, fmt.Errorf("failed to parse root certificate")
	}
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cer, err := x509.ParseCertificate(block.Bytes)
	return cer, err
}
