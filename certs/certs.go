package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func GenerateSelfSignedCert(directory string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"RegistryAuth"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(87660 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return err
	}
	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if err != nil {
		return err
	}
	certFile := filepath.Join(directory, "cert.pem")
	keyFile := filepath.Join(directory, "key.pem")
	err = os.MkdirAll(directory, 0700)
	if err != nil {
		return err
	}
	err = os.WriteFile(certFile, certPEM.Bytes(), 0600)
	if err != nil {
		return err
	}
	err = os.WriteFile(keyFile, certPrivKeyPEM.Bytes(), 0600)
	if err != nil {
		return err
	}
	return nil
}