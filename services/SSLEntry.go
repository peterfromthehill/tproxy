package services

import "bytes"

// SSLEntry holds private key and certificate for a created site
type SSLEntry struct {
	certPrivKeyPEM bytes.Buffer
	certPEM        bytes.Buffer
}
