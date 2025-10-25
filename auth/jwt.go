package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"time"

	"github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/docker/libtrust"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	log "github.com/sirupsen/logrus"
)

func CreateToken(publicKey libtrust.PublicKey, privateKey libtrust.PrivateKey, issuer string, request *Request) (string, error) {
	now := time.Now()

	claims := token.ClaimSet{
		Issuer:     issuer,
		Subject:    request.User,
		Audience:   []string{request.Service},
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
		IssuedAt:   now.Unix(),
		Expiration: now.Add(2 * time.Minute).Unix(),
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     request.ApprovedScope,
	}

	log.Debugf("Creating token for user: %s, approved scopes: %d", request.User, len(request.ApprovedScope))
	for i, scope := range request.ApprovedScope {
		log.Debugf("  Scope %d - Type: %s, Name: %s, Class: %s, Actions: %v",
			i+1, scope.Type, scope.Name, scope.Class, scope.Actions)
	}

	// Create a signer using the private key
	signerOpts := &jose.SignerOptions{}
	signerOpts = signerOpts.WithType("JWT")
	signerOpts = signerOpts.WithHeader("kid", publicKey.KeyID())

	// Get the crypto private key from libtrust
	cryptoPrivateKey := privateKey.CryptoPrivateKey()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       cryptoPrivateKey,
	}, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// Build and sign the token
	builder := jwt.Signed(signer)
	builder = builder.Claims(claims)

	tokenString, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize token: %w", err)
	}

	return tokenString, nil
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
