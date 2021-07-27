package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/docker/libtrust"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	publicKey      libtrust.PublicKey
	privateKey     libtrust.PrivateKey
	Users          map[string]string
	PublicPrefixes []string
}

type Request struct {
	User     string
	Password string
	Service  string
	Scope    []*token.ResourceActions
}

type Response struct {
	Success bool
	Token   string `json:"token"`
}

func (s *Server) HandleAuth(writer http.ResponseWriter, request *http.Request) {
	authRequest, err := s.parseRequest(request)
	if err != nil {
		http.Error(writer, "Unable to parse auth", http.StatusBadRequest)
		return
	}
	authResponse, err := s.Authenticate(authRequest)
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
	if len(authRequest.Scope) > 0 {
		err = s.Authorize(authRequest)
		if err != nil {
			http.Error(writer, fmt.Sprintf("Authorize failed: %s", err), http.StatusUnauthorized)
			return
		}
	}
	responseToken, err := s.CreateToken(authRequest)
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
		authRequest.Scope = s.parseScope(strings.Join(request.URL.Query()["scope"], " "))
	} else if request.Method == http.MethodPost {
		authRequest.Service = request.FormValue("service")
		authRequest.Scope = s.parseScope(request.FormValue("scope"))
	}
	return &authRequest, nil
}

func (s *Server) parseScope(scopes string) []*token.ResourceActions {
	resourceActions := make([]*token.ResourceActions, 0)
	scopeParts := strings.Split(scopes, " ")
	for _, scope := range scopeParts {
		if !strings.ContainsRune(scope, ':') {
			continue
		}
		splitScope := strings.Split(scope, ":")
		if len(splitScope) < 2 {
			continue
		}
		resourceActions = append(resourceActions, &token.ResourceActions{
			Type:    splitScope[0],
			Name:    strings.Join(splitScope[1:len(splitScope)-1], ""),
			Actions: strings.Split(splitScope[len(splitScope)-1], ","),
		})
	}
	return resourceActions
}

func (s *Server) Authenticate(request *Request) (authResponse *Response, err error) {
	authResponse = &Response{}
	password, ok := s.Users[request.User]
	if !ok {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(request.Password))
	if err == nil {
		authResponse.Success = true
		return
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		err = nil
	}
	return
}

func (s *Server) Authorize(request *Request) error {
	if request.Scope[0].Name == "test" {
		return fmt.Errorf("no ACL match: %s", request.Scope[0].Name)
	} else {
		return nil
	}
}

func (s *Server) CreateToken(request *Request) (string, error) {
	now := time.Now()
	header := token.Header{
		Type:       "JWT",
		SigningAlg: "RS256",
		KeyID:      s.publicKey.KeyID(),
	}
	claims := token.ClaimSet{
		Issuer:     "HGHGHGHG",
		Subject:    request.User,
		Audience:   request.Service,
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
		IssuedAt:   now.Unix(),
		Expiration: now.Add(2 * time.Minute).Unix(),
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     request.Scope,
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
