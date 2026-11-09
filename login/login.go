package login

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var (
	Issuer       = flag.String("oidc-issuer", "", "OIDC issuer URL, enables logging in to the UI")
	ClientID     = flag.String("oidc-client-id", "", "OIDC client ID")
	ClientSecret = flag.String("oidc-client-secret", "", "OIDC client secret")
	ExternalURL  = flag.String("oidc-external-url", "", "Public base URL of the UI, used to build the OIDC callback URL")
	Group        = flag.String("oidc-group", "", "Group that must be in the groups claim of the ID token")
	RequireLogin = flag.Bool("require-login", false, "Require login for all UI pages")
)

const (
	loginPath    = "/oidc/login"
	callbackPath = "/oidc/callback"
	logoutPath   = "/oidc/logout"

	sessionCookie = "registryauth_session"
	stateCookie   = "registryauth_login"

	sessionLifetime = 12 * time.Hour
	stateLifetime   = 10 * time.Minute
)

//go:embed templates
var templates embed.FS

var httpClient = &http.Client{Timeout: 10 * time.Second}

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	ExternalURL  string
	Group        string
	RequireLogin bool
}

type Authenticator struct {
	config    Config
	secure    bool
	templates *template.Template

	discoverLock sync.Mutex
	oauth        *oauth2.Config
	verifier     *oidc.IDTokenVerifier

	sessionLock sync.Mutex
	sessions    map[string]session
}

type session struct {
	user    string
	expires time.Time
}

type loginState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	ReturnTo string `json:"return_to"`
}

func New(config Config) (*Authenticator, error) {
	if config.Issuer == "" {
		if config.RequireLogin {
			return nil, errors.New("require-login needs oidc-issuer to be set")
		}
		return nil, nil
	}
	if config.ClientID == "" || config.ClientSecret == "" || config.ExternalURL == "" || config.Group == "" {
		return nil, errors.New("oidc-issuer needs oidc-client-id, oidc-client-secret, oidc-external-url and oidc-group to be set")
	}
	external, err := url.Parse(config.ExternalURL)
	if err != nil || external.Host == "" || (external.Scheme != "http" && external.Scheme != "https") {
		return nil, fmt.Errorf("oidc-external-url must be an absolute http or https URL: %q", config.ExternalURL)
	}
	config.ExternalURL = strings.TrimRight(config.ExternalURL, "/")
	authenticator := &Authenticator{
		config:    config,
		secure:    external.Scheme == "https",
		templates: template.Must(template.ParseFS(templates, "templates/*.gohtml")),
		sessions:  map[string]session{},
	}
	go func() {
		_, _, err := authenticator.discover()
		if err != nil {
			log.Warnf("Unable to reach OIDC provider, will retry on login: %s", err)
		}
	}()
	return authenticator, nil
}

func (a *Authenticator) AddRoutes(router *mux.Router) {
	router.Path(loginPath).HandlerFunc(a.HandleLogin).Methods(http.MethodGet)
	router.Path(callbackPath).HandlerFunc(a.HandleCallback).Methods(http.MethodGet)
	router.Path(logoutPath).HandlerFunc(a.HandleLogout).Methods(http.MethodPost)
}

func (a *Authenticator) User(request *http.Request) string {
	cookie, err := request.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	a.sessionLock.Lock()
	defer a.sessionLock.Unlock()
	current, ok := a.sessions[cookie.Value]
	if !ok || time.Now().After(current.expires) {
		return ""
	}
	return current.user
}

func (a *Authenticator) Protect(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "private, no-store")
		if a.config.RequireLogin && a.User(request) == "" {
			http.Redirect(writer, request, loginPath+"?return="+url.QueryEscape(request.URL.RequestURI()), http.StatusFound)
			return
		}
		next(writer, request)
	}
}

func (a *Authenticator) discover() (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	a.discoverLock.Lock()
	defer a.discoverLock.Unlock()
	if a.oauth != nil {
		return a.oauth, a.verifier, nil
	}
	// The provider keeps this context for fetching signing keys, so it must never be cancelled.
	provider, err := oidc.NewProvider(oidc.ClientContext(context.Background(), httpClient), a.config.Issuer)
	if err != nil {
		return nil, nil, err
	}
	a.verifier = provider.Verifier(&oidc.Config{ClientID: a.config.ClientID})
	a.oauth = &oauth2.Config{
		ClientID:     a.config.ClientID,
		ClientSecret: a.config.ClientSecret,
		RedirectURL:  a.config.ExternalURL + callbackPath,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "groups"},
	}
	return a.oauth, a.verifier, nil
}

func (a *Authenticator) HandleLogin(writer http.ResponseWriter, request *http.Request) {
	oauthConfig, _, err := a.discover()
	if err != nil {
		log.Errorf("Unable to reach OIDC provider: %s", err)
		http.Error(writer, "Login provider unavailable", http.StatusBadGateway)
		return
	}
	state := loginState{
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
		ReturnTo: safeReturnPath(request.URL.Query().Get("return")),
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		http.Error(writer, "Unable to start login", http.StatusInternalServerError)
		return
	}
	a.setCookie(writer, stateCookie, base64.RawURLEncoding.EncodeToString(encoded), stateLifetime)
	http.Redirect(writer, request, oauthConfig.AuthCodeURL(state.State, oidc.Nonce(state.Nonce), oauth2.S256ChallengeOption(state.Verifier)), http.StatusFound)
}

func (a *Authenticator) HandleCallback(writer http.ResponseWriter, request *http.Request) {
	state, err := readLoginState(request)
	a.clearCookie(writer, stateCookie)
	query := request.URL.Query()
	if err != nil || state.State != query.Get("state") {
		http.Error(writer, "Invalid login state, please try logging in again", http.StatusBadRequest)
		return
	}
	if providerError := query.Get("error"); providerError != "" {
		log.Infof("OIDC provider rejected login: %s", providerError)
		http.Error(writer, "Login rejected by the provider", http.StatusForbidden)
		return
	}
	user, groups, err := a.authenticate(request.Context(), query.Get("code"), state)
	if err != nil {
		log.Errorf("Login failed: %s", err)
		http.Error(writer, "Login failed", http.StatusBadGateway)
		return
	}
	if !slices.Contains(groups, a.config.Group) {
		log.Infof("Login refused: user is not in the required group: %s", user)
		http.Error(writer, "You are not permitted to log in", http.StatusForbidden)
		return
	}
	a.setCookie(writer, sessionCookie, a.createSession(user), sessionLifetime)
	http.Redirect(writer, request, state.ReturnTo, http.StatusFound)
}

func (a *Authenticator) HandleLogout(writer http.ResponseWriter, request *http.Request) {
	cookie, err := request.Cookie(sessionCookie)
	if err == nil {
		a.sessionLock.Lock()
		delete(a.sessions, cookie.Value)
		a.sessionLock.Unlock()
	}
	a.clearCookie(writer, sessionCookie)
	if a.config.RequireLogin {
		// Redirecting to a protected page would log straight back in through the provider's session.
		err = a.templates.ExecuteTemplate(writer, "loggedOut.gohtml", nil)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

func (a *Authenticator) authenticate(ctx context.Context, code string, state loginState) (string, []string, error) {
	oauthConfig, verifier, err := a.discover()
	if err != nil {
		return "", nil, err
	}
	ctx = oidc.ClientContext(ctx, httpClient)
	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(state.Verifier))
	if err != nil {
		return "", nil, fmt.Errorf("exchanging code: %s", err.Error())
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", nil, errors.New("invalid ID token: missing from token response")
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", nil, fmt.Errorf("invalid ID token: %s", err.Error())
	}
	if idToken.Nonce != state.Nonce {
		return "", nil, errors.New("invalid ID token: nonce mismatch")
	}
	var claims struct {
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	err = idToken.Claims(&claims)
	if err != nil {
		return "", nil, fmt.Errorf("invalid ID token: %s", err.Error())
	}
	user := claims.PreferredUsername
	if user == "" {
		user = idToken.Subject
	}
	return user, claims.Groups, nil
}

func (a *Authenticator) createSession(user string) string {
	id := rand.Text()
	now := time.Now()
	a.sessionLock.Lock()
	defer a.sessionLock.Unlock()
	for key := range a.sessions {
		if now.After(a.sessions[key].expires) {
			delete(a.sessions, key)
		}
	}
	a.sessions[id] = session{user: user, expires: now.Add(sessionLifetime)}
	return id
}

func (a *Authenticator) setCookie(writer http.ResponseWriter, name, value string, lifetime time.Duration) {
	http.SetCookie(writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(lifetime.Seconds()),
		HttpOnly: true,
		Secure:   a.secure,
		// Strict would withhold the state cookie on the redirect back from the provider.
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) clearCookie(writer http.ResponseWriter, name string) {
	a.setCookie(writer, name, "", -time.Second)
}

func readLoginState(request *http.Request) (loginState, error) {
	var state loginState
	cookie, err := request.Cookie(stateCookie)
	if err != nil {
		return state, err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(decoded, &state)
	if err != nil {
		return state, err
	}
	if state.State == "" {
		return state, errors.New("empty login state")
	}
	// The cookie is client-held, so it is not trusted to contain a local path.
	state.ReturnTo = safeReturnPath(state.ReturnTo)
	return state, nil
}

func safeReturnPath(target string) string {
	// Browsers treat backslashes as slashes and strip control characters.
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") ||
		strings.Contains(target, `\`) || strings.IndexFunc(target, unicode.IsControl) != -1 {
		return "/"
	}
	return target
}
