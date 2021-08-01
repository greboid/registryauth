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
	authRequest := parseRequest(s.Users, request)
	if len(authRequest.RequestedScope) > 0 {
		approvedScope, err := authorise(s.PublicPrefixes, authRequest)
		if err == nil {
			authRequest.ApprovedScope = approvedScope
		} else {
			log.Infof("authorise failed: %s", err)
		}
	} else {
		if !authRequest.validCredentials {
			log.Infof("authenticate failed: %s", authRequest.User)
			writer.Header().Set("WWW-authenticate", fmt.Sprintf(`Basic realm="%s"`, s.Realm))
			http.Error(writer, "authenticate failed", http.StatusUnauthorized)
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

func parseRequest(users map[string]string, request *http.Request) *Request {
	authRequest := &Request{}
	authRequest.User, authRequest.Password = getAuth(request)
	authRequest.Service = parseRequestService(request)
	authRequest.RequestedScope = parseScope(parseRequestScope(request))
	authRequest.validCredentials = authenticate(users, authRequest)
	return authRequest
}

func parseRequestScope(request *http.Request) string {
	if request.Method == http.MethodGet {
		return strings.Join(request.URL.Query()["scope"], " ")
	} else if request.Method == http.MethodPost {
		return request.FormValue("scope")
	}
	return ""
}

func parseRequestService(request *http.Request) string {
	if request.Method == http.MethodGet {
		return request.URL.Query().Get("service")
	} else if request.Method == http.MethodPost {
		return request.FormValue("service")
	}
	return ""
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

func parseScope(scopes string) []*token.ResourceActions {
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

func authenticate(users map[string]string, request *Request) bool {
	password, ok := users[request.User]
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(password), []byte(request.Password)) == nil
}

func isScopePublic(publicPrefixes []string, scopeItem *token.ResourceActions) bool {
	if scopeItem.Type != "repository" {
		return false
	}
	for _, publicPrefix := range publicPrefixes {
		if len(scopeItem.Name) > len(publicPrefix+"/") &&
			strings.HasPrefix(scopeItem.Name, publicPrefix+"/") {
			return true
		}
	}
	return false
}

func sanitiseScope(scope *token.ResourceActions, isPublic bool, validCredentials bool) *token.ResourceActions {
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

func authorise(publicPrefixes []string, request *Request) ([]*token.ResourceActions, error) {
	approvedScopes := make([]*token.ResourceActions, 0)
	for _, scopeItem := range request.RequestedScope {
		if scope := sanitiseScope(scopeItem, isScopePublic(publicPrefixes, scopeItem), request.validCredentials); scope != nil {
			approvedScopes = append(approvedScopes, scope)
		}
	}
	return approvedScopes, nil
}
