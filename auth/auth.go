package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/docker/libtrust"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	publicKey libtrust.PublicKey
	privateKey libtrust.PrivateKey
}

type Request struct {
	User string
	Password string
	Service string
	Scope []string
}

type Response struct {
	Success bool
	Token string `json:"token"`
}

func (s *Server) HandleAuth(writer http.ResponseWriter, request *http.Request) {
	authRequest, err := s.parseRequest(request)
	if err != nil {
		http.Error(writer, "Unable to parse auth", http.StatusBadRequest)
		return
	}
	authResponse, err := authRequest.Authenticate()
	if err != nil {
		http.Error(writer, fmt.Sprintf("Authentication failed (%s)", err), http.StatusInternalServerError)
		return
	}
	if !authResponse.Success {
		log.Printf("Auth failed: %+v", authResponse)
		writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, "HGHGHGHG"))
		http.Error(writer, "Authenticate failed", http.StatusUnauthorized)
		return
	}
	if len(authRequest.Scope) == 0 {
		err = authRequest.Authorize()
		http.Error(writer, fmt.Sprintf("Authorize failed: %s", err), http.StatusInternalServerError)
		return
	}
	responseToken, err := authRequest.CreateToken(s)
	if err != nil {
		log.Printf("Unable to create token: %s", err)
		http.Error(writer, "Unable to create token", http.StatusInternalServerError)
		return
	}
	//Bodge access_token and token to support old clients, but not sure I care
	result, _ := json.Marshal(&map[string]string{"access_token": responseToken, "token": responseToken})
	_, _ = writer.Write(result)
}

func (s *Server) parseRequest(request *http.Request) (*Request, error) {
	authRequest := Request{}
	user, password, haveBasicAuth := request.BasicAuth()
	if haveBasicAuth {
		authRequest.User = user
		authRequest.Password = password
	} else if request.Method == http.MethodPost {
		formUser := request.FormValue("username")
		formPass := request.FormValue("password")
		if formUser != "" && formPass != "" {
			authRequest.User = formUser
			authRequest.Password = formPass
		}
	}
	if request.Method == http.MethodGet {
		authRequest.Service = request.URL.Query().Get("service")
		authRequest.Scope = s.parseScope(request.URL.Query().Get("scope"))
	} else if request.Method == http.MethodGet {
		authRequest.Service = request.FormValue("service")
		authRequest.Scope = s.parseScope(request.FormValue("scope"))
	}
	return &authRequest, nil
}

func (s *Server) parseScope(scope string) []string {
	log.Printf("Scope: %s", scope)
	return []string{scope}
}

func (a *Request) Authenticate() (*Response, error) {
	authResponse := Response{}
	authResponse.Success = true
	return &authResponse, nil
}

func (a *Request) Authorize() error {
	return nil
}

func (a *Request) CreateToken(s *Server) (string, error) {
	now := time.Now()
	header := token.Header{
		Type:       "JWT",
		SigningAlg: "RS256",
		KeyID:      s.publicKey.KeyID(),
	}
	claims := token.ClaimSet{
		Issuer:     "HGHGHGHG",
		Subject:    a.User,
		Audience:   a.Service,
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
		IssuedAt:   now.Unix(),
		Expiration: now.Add(2 * time.Minute).Unix(),
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     []*token.ResourceActions{},
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