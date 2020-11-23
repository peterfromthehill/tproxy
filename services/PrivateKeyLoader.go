package services

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

type PrivateKeyLoader struct {
	file string
}

func (this PrivateKeyLoader) loadPKfromFile() (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(this.file)
	if err != nil {
		return nil, err
	}

	key, err := parsePrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", this.file, err)
	}
	return key, nil
}

func parsePrivateKey(privKey []byte) (*rsa.PrivateKey, error) {
	privPem, _ := pem.Decode(privKey)
	var privPemBytes []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("RSA private key is of the wrong type")
	}

	privPemBytes = privPem.Bytes
	key, err := x509.ParsePKCS1PrivateKey(privPemBytes)
	return key, err
}
