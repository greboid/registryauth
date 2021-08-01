package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/docker/libtrust"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type Request struct {
	User             string
	Password         string
	Service          string
	ApprovedScope    []*token.ResourceActions
	RequestedScope   []*token.ResourceActions
	validCredentials bool
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
	authRequest.validCredentials = s.Authenticate(authRequest)
	if len(authRequest.RequestedScope) > 0 {
		approvedScope, err := s.Authorize(authRequest)
		if err != nil {
			log.Infof("Authorize failed: %s", err)
			http.Error(writer, fmt.Sprintf("Authorize failed: %s", err), http.StatusUnauthorized)
			return
		}
		authRequest.ApprovedScope = approvedScope
	} else {
		if !authRequest.validCredentials {
			log.Infof("Authenticate failed: %s", authRequest.User)
			writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, s.Realm))
			http.Error(writer, "Authenticate failed", http.StatusUnauthorized)
			return
		}
	}
	responseToken, err := s.CreateToken(authRequest)
	if err != nil {
		log.Errorf("Unable to create token: %s", err)
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
		authRequest.RequestedScope = s.parseScope(strings.Join(request.URL.Query()["scope"], " "))
	} else if request.Method == http.MethodPost {
		authRequest.Service = request.FormValue("service")
		authRequest.RequestedScope = s.parseScope(request.FormValue("scope"))
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
			Name:    strings.Join(splitScope[1:len(splitScope)-1], ":"),
			Actions: strings.Split(splitScope[len(splitScope)-1], ","),
		})
	}
	return resourceActions
}

func (s *Server) Authenticate(request *Request) bool {
	password, ok := s.Users[request.User]
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(password), []byte(request.Password)) == nil
}

func ScopeIsPull(item *token.ResourceActions) bool {
	if len(item.Actions) == 1 {
		return item.Actions[0] == "pull"
	}
	return false
}

func (s *Server) isScopePublic(scopeItem *token.ResourceActions) bool {
	for _, publicPrefix := range s.PublicPrefixes {
		if strings.HasPrefix(scopeItem.Name, publicPrefix) {
			return true
		}
	}
	return false
}

func (s *Server) sanitiseScope(scope *token.ResourceActions, isPublic bool, validCredentials bool) *token.ResourceActions {
	newScope := &token.ResourceActions{
		Type:    scope.Type,
		Class:   scope.Class,
		Name:    scope.Name,
		Actions: scope.Actions,
	}
	if validCredentials {
		return newScope
	}
	if !isPublic {
		return nil
	}
	if !ScopeIsPull(scope) {
		newScope.Actions = []string{"pull"}
		return newScope
	}
	return newScope
}

func (s *Server) Authorize(request *Request) ([]*token.ResourceActions, error) {
	approvedScopes := make([]*token.ResourceActions, 0)
	for _, scopeItem := range request.RequestedScope {
		if scope := s.sanitiseScope(scopeItem, s.isScopePublic(scopeItem), request.validCredentials); scope != nil {
			approvedScopes = append(approvedScopes, scope)
		}
	}
	return approvedScopes, nil
}

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
