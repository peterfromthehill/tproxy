package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"go.elastic.co/apm"
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
		panic(err)
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
	cacheService.Watch()
	return cer, key, nil
}

func createCertificateTemplate(serverName string, minutes time.Duration) *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Minute * minutes),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if ip := net.ParseIP(serverName); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	} else {
		cert.DNSNames = append(cert.DNSNames, serverName)
	}
	return cert
}

func GenerateCertByName(serverName string) (*tls.Certificate, error) {
	tx := apm.DefaultTracer.StartTransaction("ReturnCert("+serverName+")", "request")
	defer tx.End()
	ctx := apm.ContextWithTransaction(context.TODO(), tx)
	tx.Context.SetLabel("inCache", "false")
	cacheService := GetCacheService()
	if serverCert, err := cacheService.FindCertinCache(serverName); err == nil {
		tx.Context.SetLabel("inCache", "true")
		return serverCert, nil
	}
	// set up our server certificate
	cert := createCertificateTemplate(serverName, 60*24)

	keyGenSpan, ctx := apm.StartSpan(ctx, "GenerateKey("+serverName+")", "request")
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", serverName, err)
	}
	keyGenSpan.End()

	createCertSpan, ctx := apm.StartSpan(ctx, "CreateCertificate("+serverName+")", "request")
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCer, &certPrivKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", serverName, err)
	}
	createCertSpan.End()

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	sslentry := SSLEntry{*certPrivKeyPEM, *certPEM}
	cacheService.Add(serverName, sslentry)

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%s: %s", serverName, err)
	}

	return &serverCert, nil
}

func ReturnCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return GenerateCertByName(helloInfo.ServerName)
}
