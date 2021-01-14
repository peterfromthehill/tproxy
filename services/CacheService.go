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
	"log"
	"math/big"
	"net"
	"time"

	"go.elastic.co/apm"
)

// SSLCache cached TLS certificates from sites visited in the history
var SSLCache map[string]SSLEntry

type CacheService struct {
}

func (this CacheService) makeAndWatch() {
	SSLCache = make(map[string]SSLEntry)
	go sslCacheWatcher(10)
}

func sslCacheWatcher(interval time.Duration) {
	for {
		sslCacheWatcher0()
		time.Sleep(interval * time.Second)
	}
}

func sslCacheWatcher0() {
	for i, v := range SSLCache {
		cer, err := parseX509Cert(v.certPEM.Bytes())
		if err != nil {
			log.Printf("%s: invalid cert!", i)
			continue
		}
		if cer.NotAfter.Before(time.Now().Add(time.Minute * 5)) {
			log.Printf("%s: cert expired, delete it from cache", i)
			delete(SSLCache, i)
			continue
		}
		log.Printf("%s %s\n", i, cer.NotAfter)
	}
}

func findCertinCache(serverName string) (*tls.Certificate, error) {
	if sslEntry, ok := SSLCache[serverName]; ok != false {
		serverCert, err := tls.X509KeyPair(sslEntry.certPEM.Bytes(), sslEntry.certPrivKeyPEM.Bytes())
		if err != nil {
			return nil, err
		}
		return &serverCert, nil
	}
	return nil, fmt.Errorf("%s Cert not found in cache", serverName)
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

func ReturnCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	tx := apm.DefaultTracer.StartTransaction("ReturnCert("+helloInfo.ServerName+")", "request")
	defer tx.End()
	ctx := apm.ContextWithTransaction(context.TODO(), tx)
	tx.Context.SetLabel("inCache", "false")
	if serverCert, err := findCertinCache(helloInfo.ServerName); err == nil {
		tx.Context.SetLabel("inCache", "true")
		return serverCert, nil
	}
	// set up our server certificate
	cert := createCertificateTemplate(helloInfo.ServerName, 60*24)

	keyGenSpan, ctx := apm.StartSpan(ctx, "GenerateKey("+helloInfo.ServerName+")", "request")
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", helloInfo.ServerName, err)
	}
	keyGenSpan.End()

	createCertSpan, ctx := apm.StartSpan(ctx, "CreateCertificate("+helloInfo.ServerName+")", "request")
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCer, &certPrivKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", helloInfo.ServerName, err)
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
	SSLCache[helloInfo.ServerName] = sslentry

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%s: %s", helloInfo.ServerName, err)
	}

	return &serverCert, nil
}
