package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func GenerateSelfSignedCert(certPath string, keyPath string) error {
	if checkExist(certPath, keyPath) && checkValid(certPath, keyPath) {
		return nil
	}
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
	err = os.MkdirAll(filepath.Dir(certPath), 0711)
	if err != nil {
		return err
	}
	err = os.MkdirAll(filepath.Dir(keyPath), 0711)
	if err != nil {
		return err
	}
	err = os.WriteFile(certPath, certPEM.Bytes(), 0644)
	if err != nil {
		return err
	}
	err = os.WriteFile(keyPath, certPrivKeyPEM.Bytes(), 0600)
	if err != nil {
		return err
	}
	return nil
}

func checkExist(certPath string, keyPath string) bool {
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		return false
	}
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func checkValid(certPath string, keyPath string) bool {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return false
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	if !time.Now().After(x509Cert.NotAfter) {
		return false
	}
	if !time.Now().Before(x509Cert.NotBefore) {
		return false
	}
	return true
}
