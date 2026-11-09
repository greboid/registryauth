package login

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gorilla/mux"
)

const (
	testClient = "client"
	testSecret = "secret"
	testGroup  = "admins"
)

type fakeProvider struct {
	t         *testing.T
	server    *httptest.Server
	key       *rsa.PrivateKey
	groups    any
	nonce     string
	challenge string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeProvider{t: t, key: key, groups: []string{testGroup}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"issuer":                                provider.server.URL,
			"authorization_endpoint":                provider.server.URL + "/authorize",
			"token_endpoint":                        provider.server.URL + "/token",
			"jwks_uri":                              provider.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: "test", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", provider.handleToken)
	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *fakeProvider) handleToken(writer http.ResponseWriter, request *http.Request) {
	digest := sha256.Sum256([]byte(request.FormValue("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(digest[:]) != p.challenge {
		http.Error(writer, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithHeader("kid", "test"))
	if err != nil {
		p.t.Error(err)
		return
	}
	idToken, err := jwt.Signed(signer).Claims(map[string]any{
		"iss":                p.server.URL,
		"aud":                testClient,
		"sub":                "subject",
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Unix(),
		"nonce":              p.nonce,
		"preferred_username": "alice",
		"groups":             p.groups,
	}).Serialize()
	if err != nil {
		p.t.Error(err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"access_token": "access", "token_type": "Bearer", "id_token": idToken,
	})
}

func newAuthenticator(t *testing.T, provider *fakeProvider, requireLogin bool) (*Authenticator, *mux.Router) {
	t.Helper()
	authenticator, err := New(Config{
		Issuer:       provider.server.URL,
		ClientID:     testClient,
		ClientSecret: testSecret,
		ExternalURL:  "http://app.example/",
		Group:        testGroup,
		RequireLogin: requireLogin,
	})
	if err != nil {
		t.Fatal(err)
	}
	router := mux.NewRouter()
	authenticator.AddRoutes(router)
	return authenticator, router
}

func serve(router http.Handler, method, target string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)
	return writer
}

func requestWith(cookies []*http.Cookie) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return request
}

func startLogin(t *testing.T, provider *fakeProvider, router http.Handler, returnTo string) (url.Values, []*http.Cookie) {
	t.Helper()
	writer := serve(router, http.MethodGet, "/oidc/login?return="+url.QueryEscape(returnTo), nil)
	if writer.Code != http.StatusFound {
		t.Fatalf("expected redirect to provider, got %d: %s", writer.Code, writer.Body.String())
	}
	location, err := url.Parse(writer.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	if query.Get("redirect_uri") != "http://app.example/oidc/callback" {
		t.Errorf("unexpected redirect_uri: %q", query.Get("redirect_uri"))
	}
	if !strings.Contains(query.Get("scope"), "groups") {
		t.Errorf("groups scope not requested: %q", query.Get("scope"))
	}
	provider.nonce = query.Get("nonce")
	provider.challenge = query.Get("code_challenge")
	return query, writer.Result().Cookies()
}

func callbackURL(state string) string {
	return "/oidc/callback?code=code&state=" + url.QueryEscape(state)
}

func TestAuthenticator_loginSuccess(t *testing.T) {
	provider := newFakeProvider(t)
	authenticator, router := newAuthenticator(t, provider, false)
	query, cookies := startLogin(t, provider, router, "/private/repo")

	writer := serve(router, http.MethodGet, callbackURL(query.Get("state")), cookies)
	if writer.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d: %s", writer.Code, writer.Body.String())
	}
	if location := writer.Header().Get("Location"); location != "/private/repo" {
		t.Errorf("expected return to original page, got %q", location)
	}
	session := writer.Result().Cookies()
	if user := authenticator.User(requestWith(session)); user != "alice" {
		t.Errorf("expected alice, got %q", user)
	}
	for _, cookie := range session {
		if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie %s has unsafe attributes", cookie.Name)
		}
	}
}

func TestAuthenticator_HandleCallbackRejected(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(provider *fakeProvider)
		state    func(state string) string
		wantCode int
	}{
		{
			name:     "not in group",
			mutate:   func(p *fakeProvider) { p.groups = []string{"other"} },
			wantCode: http.StatusForbidden,
		},
		{
			name:     "no groups",
			mutate:   func(p *fakeProvider) { p.groups = nil },
			wantCode: http.StatusForbidden,
		},
		{
			name:     "wrong nonce",
			mutate:   func(p *fakeProvider) { p.nonce = "other" },
			wantCode: http.StatusBadGateway,
		},
		{
			name:     "wrong pkce",
			mutate:   func(p *fakeProvider) { p.challenge = "other" },
			wantCode: http.StatusBadGateway,
		},
		{
			name:     "wrong state",
			state:    func(string) string { return "other" },
			wantCode: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newFakeProvider(t)
			authenticator, router := newAuthenticator(t, provider, false)
			query, cookies := startLogin(t, provider, router, "/")
			if tt.mutate != nil {
				tt.mutate(provider)
			}
			state := query.Get("state")
			if tt.state != nil {
				state = tt.state(state)
			}
			writer := serve(router, http.MethodGet, callbackURL(state), cookies)
			if writer.Code != tt.wantCode {
				t.Errorf("HandleCallback() code = %v, want %v: %s", writer.Code, tt.wantCode, writer.Body.String())
			}
			for _, cookie := range writer.Result().Cookies() {
				if cookie.Name == sessionCookie {
					t.Error("session cookie issued for rejected login")
				}
			}
			if len(authenticator.sessions) != 0 {
				t.Error("session created for rejected login")
			}
		})
	}
}

func TestAuthenticator_HandleCallbackWithoutStateCookie(t *testing.T) {
	provider := newFakeProvider(t)
	_, router := newAuthenticator(t, provider, false)
	writer := serve(router, http.MethodGet, callbackURL("state"), nil)
	if writer.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", writer.Code)
	}
}

func TestAuthenticator_HandleCallbackProviderError(t *testing.T) {
	provider := newFakeProvider(t)
	_, router := newAuthenticator(t, provider, false)
	query, cookies := startLogin(t, provider, router, "/")
	writer := serve(router, http.MethodGet, callbackURL(query.Get("state"))+"&error=access_denied", cookies)
	if writer.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", writer.Code)
	}
}

func TestAuthenticator_HandleLogout(t *testing.T) {
	tests := []struct {
		name         string
		requireLogin bool
		wantCode     int
		wantContains string
	}{
		{
			name:         "login optional",
			requireLogin: false,
			wantCode:     http.StatusSeeOther,
		},
		{
			name:         "login required",
			requireLogin: true,
			wantCode:     http.StatusOK,
			wantContains: "You have been logged out.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newFakeProvider(t)
			authenticator, router := newAuthenticator(t, provider, tt.requireLogin)
			query, cookies := startLogin(t, provider, router, "/")
			session := serve(router, http.MethodGet, callbackURL(query.Get("state")), cookies).Result().Cookies()
			var sessionOnly []*http.Cookie
			for _, cookie := range session {
				if cookie.Name == sessionCookie {
					sessionOnly = append(sessionOnly, cookie)
				}
			}

			writer := serve(router, http.MethodPost, "/oidc/logout", sessionOnly)
			if writer.Code != tt.wantCode {
				t.Errorf("HandleLogout() code = %v, want %v", writer.Code, tt.wantCode)
			}
			if !strings.Contains(writer.Body.String(), tt.wantContains) {
				t.Errorf("HandleLogout() body = %q, want to contain %q", writer.Body.String(), tt.wantContains)
			}
			if user := authenticator.User(requestWith(sessionOnly)); user != "" {
				t.Errorf("session still valid after logout: %q", user)
			}
		})
	}
}

func TestAuthenticator_HandleLogoutRejectsGet(t *testing.T) {
	provider := newFakeProvider(t)
	_, router := newAuthenticator(t, provider, false)
	if writer := serve(router, http.MethodGet, "/oidc/logout", nil); writer.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", writer.Code)
	}
}

func TestAuthenticator_expiredSession(t *testing.T) {
	authenticator := &Authenticator{sessions: map[string]session{"old": {user: "alice", expires: time.Now().Add(-time.Minute)}}}
	cookies := []*http.Cookie{{Name: sessionCookie, Value: "old"}}
	if user := authenticator.User(requestWith(cookies)); user != "" {
		t.Errorf("expired session accepted for %q", user)
	}
	authenticator.createSession("bob")
	if _, ok := authenticator.sessions["old"]; ok {
		t.Error("expired session was not purged")
	}
}

func TestAuthenticator_Protect(t *testing.T) {
	next := func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusTeapot) }
	active := &Authenticator{sessions: map[string]session{"id": {user: "alice", expires: time.Now().Add(time.Hour)}}}
	loggedIn := []*http.Cookie{{Name: sessionCookie, Value: "id"}}

	tests := []struct {
		name         string
		requireLogin bool
		cookies      []*http.Cookie
		wantCode     int
	}{
		{
			name:         "optional anonymous",
			requireLogin: false,
			cookies:      nil,
			wantCode:     http.StatusTeapot,
		},
		{
			name:         "optional logged in",
			requireLogin: false,
			cookies:      loggedIn,
			wantCode:     http.StatusTeapot,
		},
		{
			name:         "required anonymous",
			requireLogin: true,
			cookies:      nil,
			wantCode:     http.StatusFound,
		},
		{
			name:         "required logged in",
			requireLogin: true,
			cookies:      loggedIn,
			wantCode:     http.StatusTeapot,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			active.config.RequireLogin = tt.requireLogin
			writer := serve(active.Protect(next), http.MethodGet, "/private/repo?a=b", tt.cookies)
			if writer.Code != tt.wantCode {
				t.Errorf("Protect() code = %v, want %v", writer.Code, tt.wantCode)
			}
			if tt.wantCode == http.StatusFound {
				if location := writer.Header().Get("Location"); location != "/oidc/login?return=%2Fprivate%2Frepo%3Fa%3Db" {
					t.Errorf("unexpected redirect %q", location)
				}
			}
			if writer.Header().Get("Cache-Control") != "private, no-store" {
				t.Errorf("page may be cached: %q", writer.Header().Get("Cache-Control"))
			}
		})
	}
}

func Test_safeReturnPath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Root",
			input: "/",
			want:  "/",
		},
		{
			name:  "Local path with query",
			input: "/public/repo?a=b",
			want:  "/public/repo?a=b",
		},
		{
			name:  "Empty",
			input: "",
			want:  "/",
		},
		{
			name:  "Relative path",
			input: "public/repo",
			want:  "/",
		},
		{
			name:  "Absolute URL",
			input: "https://evil.example",
			want:  "/",
		},
		{
			name:  "Protocol relative",
			input: "//evil.example",
			want:  "/",
		},
		{
			name:  "Backslash",
			input: `/\evil.example`,
			want:  "/",
		},
		{
			name:  "Tab",
			input: "/\t/evil.example",
			want:  "/",
		},
		{
			name:  "Newline",
			input: "/\n/evil.example",
			want:  "/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeReturnPath(tt.input); got != tt.want {
				t.Errorf("safeReturnPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_New(t *testing.T) {
	valid := Config{Issuer: "http://127.0.0.1:1", ClientID: "c", ClientSecret: "s", ExternalURL: "https://a.example", Group: "g"}
	without := func(change func(config *Config)) Config {
		config := valid
		change(&config)
		return config
	}
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		wantNil bool
	}{
		{
			name:    "disabled",
			config:  Config{},
			wantErr: false,
			wantNil: true,
		},
		{
			name:    "require login without issuer",
			config:  Config{RequireLogin: true},
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "valid",
			config:  valid,
			wantErr: false,
			wantNil: false,
		},
		{
			name:    "no client",
			config:  without(func(c *Config) { c.ClientID = "" }),
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "no secret",
			config:  without(func(c *Config) { c.ClientSecret = "" }),
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "no external url",
			config:  without(func(c *Config) { c.ExternalURL = "" }),
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "no group",
			config:  without(func(c *Config) { c.Group = "" }),
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "relative external url",
			config:  without(func(c *Config) { c.ExternalURL = "a.example" }),
			wantErr: true,
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticator, err := New(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (authenticator == nil) != tt.wantNil {
				t.Errorf("New() = %v, wantNil %v", authenticator, tt.wantNil)
			}
		})
	}
}

func TestAuthenticator_secureCookies(t *testing.T) {
	provider := newFakeProvider(t)
	authenticator, err := New(Config{Issuer: provider.server.URL, ClientID: testClient, ClientSecret: testSecret, ExternalURL: "https://a.example", Group: testGroup})
	if err != nil {
		t.Fatal(err)
	}
	writer := httptest.NewRecorder()
	authenticator.setCookie(writer, "name", "value", time.Minute)
	if !writer.Result().Cookies()[0].Secure {
		t.Error("expected secure cookie for https external URL")
	}
}
