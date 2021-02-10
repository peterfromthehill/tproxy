package services

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

type PrivateKeyLoader struct {
	file string
}

func (privateKeyLoader PrivateKeyLoader) loadPKfromFile() (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(privateKeyLoader.file)
	if err != nil {
		return nil, err
	}

	key, err := privateKeyLoader.parsePrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", privateKeyLoader.file, err)
	}
	return key, nil
}

func (privateKeyLoader PrivateKeyLoader) parsePrivateKey(privKey []byte) (*rsa.PrivateKey, error) {
	privPem, _ := pem.Decode(privKey)
	privatePkcs1Key, errPkcs1 := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if errPkcs1 == nil {
		return privatePkcs1Key, nil
	}
	privatePkcs8Key, errPkcs8 := x509.ParsePKCS8PrivateKey(privPem.Bytes)
	if errPkcs8 == nil {
		privatePkcs8RsaKey, ok := privatePkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Pkcs8 contained non-RSA key. Expected RSA key")
		}
		return privatePkcs8RsaKey, nil
	}
	return nil, fmt.Errorf("Failed to parse private key as Pkcs#1 or Pkcs#8\n\n%s\n\n%s", errPkcs1, errPkcs8)
}
