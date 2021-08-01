package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/distribution/distribution/v3/registry/auth/token"
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
	authRequest := s.parseRequest(request)
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
	//Bodge access_token and token to support old clients, but not sure if I care
	result, _ := json.Marshal(&map[string]string{"access_token": responseToken, "token": responseToken})
	_, _ = writer.Write(result)
}

func (s *Server) parseRequest(request *http.Request) *Request {
	authRequest := Request{}
	authRequest.User, authRequest.Password = getAuth(request)
	if request.Method == http.MethodGet {
		authRequest.Service = request.URL.Query().Get("service")
		authRequest.RequestedScope = s.parseScope(strings.Join(request.URL.Query()["scope"], " "))
	} else if request.Method == http.MethodPost {
		authRequest.Service = request.FormValue("service")
		authRequest.RequestedScope = s.parseScope(request.FormValue("scope"))
	}
	return &authRequest
}

func getAuth(request *http.Request) (string, string) {
	user, password, haveBasicAuth := request.BasicAuth()
	if haveBasicAuth {
		return user, password
	} else if request.Method == http.MethodPost {
		formUser := request.FormValue("username")
		formPass := request.FormValue("password")
		if formUser != "" && formPass != "" {
			return formUser, formPass
		}
	}
	return "", ""
}

func (s *Server) parseScope(scopes string) []*token.ResourceActions {
	resourceActions := make([]*token.ResourceActions, 0)
	scopeParts := strings.Split(scopes, " ")
	for _, scope := range scopeParts {
		if !strings.ContainsRune(scope, ':') {
			continue
		}
		splitScope := strings.Split(scope, ":")
		if len(splitScope) <= 2 {
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

func (s *Server) isScopePublic(scopeItem *token.ResourceActions) bool {
	if scopeItem.Type != "repository" {
		return false
	}
	for _, publicPrefix := range s.PublicPrefixes {
		if len(scopeItem.Name) > len(publicPrefix+"/") &&
			strings.HasPrefix(scopeItem.Name, publicPrefix+"/") {
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
	if len(scope.Actions) > 1 || scope.Actions[0] != "pull" {
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
