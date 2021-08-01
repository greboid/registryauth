package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/docker/libtrust"
)

func (s *Server) CreateToken(request *Request) (string, error) {
	now := time.Now()
	header := token.Header{
		Type:       "JWT",
		SigningAlg: "RS256",
		KeyID:      s.publicKey.KeyID(),
	}
	claims := token.ClaimSet{
		Issuer:     s.Issuer,
		Subject:    request.User,
		Audience:   request.Service,
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
		IssuedAt:   now.Unix(),
		Expiration: now.Add(2 * time.Minute).Unix(),
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     request.ApprovedScope,
	}
	headerJson, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJson, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := fmt.Sprintf("%s%s%s", joseBase64UrlEncode(headerJson), token.TokenSeparator, joseBase64UrlEncode(claimsJson))
	sig, _, err := s.privateKey.Sign(strings.NewReader(payload), 0)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, joseBase64UrlEncode(sig)), nil
}

//Copied from libtrust
func joseBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func (s *Server) LoadCertAndKey(certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	pk, err := libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return err
	}
	prk, err := libtrust.FromCryptoPrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	s.publicKey = pk
	s.privateKey = prk
	return nil
}
