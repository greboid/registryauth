package auth

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/distribution/distribution/v3/registry/auth/token"
)

func actionsToString(a []*token.ResourceActions) string {
	if a == nil {
		return "nil"
	}
	if len(a) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(actionToString(a[0]))
	for _, s := range a[1:] {
		b.WriteString(", ")
		b.WriteString(actionToString(s))
	}
	return b.String()
}

func actionToString(a *token.ResourceActions) string {
	return fmt.Sprintf("%s", a)
}

func TestServer_Authorize(t *testing.T) {
	tests := []struct {
		name               string
		publicPrefixes     []string
		request            *Request
		wantApprovedScopes []*token.ResourceActions
		wantErr            bool
	}{
		{
			name:           "ValidAuth-WantTest-IsPublic",
			publicPrefixes: []string{"test"},
			request: &Request{
				User: "greboid",
				RequestedScope: []*token.ResourceActions{
					{
						Type:    "repository",
						Name:    "test/test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: true,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Type:    "repository",
					Name:    "test/test",
					Actions: []string{"pull"},
				},
			},
			wantErr: false,
		},
		{
			name:           "ValidAuth-WantTest-IsPublic",
			publicPrefixes: []string{"test"},
			request: &Request{
				User: "greboid",
				RequestedScope: []*token.ResourceActions{
					{
						Type:    "repository",
						Name:    "test/test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: true,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Type:    "repository",
					Name:    "test/test",
					Actions: []string{"pull"},
				},
			},
			wantErr: false,
		},
		{
			name:           "InvalidAuth-WantTest-IsPublic-Push",
			publicPrefixes: []string{"test"},
			request: &Request{
				User: "greboid",
				RequestedScope: []*token.ResourceActions{
					{
						Type:    "repository",
						Name:    "test/test",
						Actions: []string{"push", "pull"},
					},
				},
				validCredentials: false,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Type:    "repository",
					Name:    "test/test",
					Actions: []string{"pull"},
				},
			},
			wantErr: false,
		},
		{
			name:           "InvalidAuth-WantTest-IsPublic-Pull",
			publicPrefixes: []string{"test"},
			request: &Request{
				User: "greboid",
				RequestedScope: []*token.ResourceActions{
					{
						Type:    "repository",
						Name:    "test/test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: false,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Type:    "repository",
					Name:    "test/test",
					Actions: []string{"pull"},
				},
			},
			wantErr: false,
		},
		{
			name:           "ValidAuth-WantTest-NotPublic",
			publicPrefixes: []string{},
			request: &Request{
				User: "greboid",
				RequestedScope: []*token.ResourceActions{
					{
						Type:    "repository",
						Name:    "test/test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: true,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Type:    "repository",
					Name:    "test/test",
					Actions: []string{"pull"},
				},
			},
			wantErr: false,
		},
		{
			name:           "InvalidAuth-WantTest-NotPublic",
			publicPrefixes: []string{},
			request: &Request{
				User: "greboid",
				RequestedScope: []*token.ResourceActions{
					{
						Type:    "repository",
						Name:    "test/test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: false,
			},
			wantApprovedScopes: []*token.ResourceActions{},
			wantErr:            false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				PublicPrefixes: tt.publicPrefixes,
			}
			gotApprovedScopes, err := s.Authorize(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authorize() error = %#v, wantErr %#v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotApprovedScopes, tt.wantApprovedScopes) {
				t.Errorf("parseScope() = %#+v, want %#+v", actionsToString(gotApprovedScopes), actionsToString(tt.wantApprovedScopes))
			}
		})
	}
}

func TestServer_parseScope(t *testing.T) {
	tests := []struct {
		name   string
		scopes string
		want   []*token.ResourceActions
	}{
		{
			name:   "Repository empty scope",
			scopes: "",
			want:   []*token.ResourceActions{},
		},
		{
			name:   "Repository invalid scope",
			scopes: "repository:imageName",
			want:   []*token.ResourceActions{},
		},
		{
			name:   "Repository with value",
			scopes: "resourceType(resourceValue):imageName:pull",
			want: []*token.ResourceActions{
				{
					Type:    "resourceType(resourceValue)",
					Name:    "imageName",
					Actions: []string{"pull"},
				},
			},
		},
		{
			name:   "Repository one action",
			scopes: "resourceType:imageName:pull",
			want: []*token.ResourceActions{
				{
					Type:    "resourceType",
					Name:    "imageName",
					Actions: []string{"pull"},
				},
			},
		},
		{
			name:   "Repository with multi part component",
			scopes: "resourceType:registryName/component/component:pull",
			want: []*token.ResourceActions{
				{
					Type:    "resourceType",
					Name:    "registryName/component/component",
					Actions: []string{"pull"},
				},
			},
		},

		{
			name:   "Repository with registry with port and multi part component",
			scopes: "resourceType:registryName:8080/component/component:pull",
			want: []*token.ResourceActions{
				{
					Type:    "resourceType",
					Name:    "registryName:8080/component/component",
					Actions: []string{"pull"},
				},
			},
		},
		{
			name:   "Multiple actions",
			scopes: "resourceType:imageName:pull,push",
			want: []*token.ResourceActions{
				{
					Type:    "resourceType",
					Name:    "imageName",
					Actions: []string{"pull", "push"},
				},
			},
		},
		{
			name:   "Image with port",
			scopes: "resourceType:registryName:8080:pull",
			want: []*token.ResourceActions{
				{
					Type:    "resourceType",
					Name:    "registryName:8080",
					Actions: []string{"pull"},
				},
			},
		},
		{
			name:   "Image with port and path",
			scopes: "resourceType:registryName:8080/imageName:pull",
			want: []*token.ResourceActions{
				{
					Type:    "resourceType",
					Name:    "registryName:8080/imageName",
					Actions: []string{"pull"},
				},
			},
		},
		{
			name:   "Image with port and path and tag",
			scopes: "resourceType:registryName:8080/imageName:tagName:pull",
			want: []*token.ResourceActions{
				{
					Type:    "resourceType",
					Name:    "registryName:8080/imageName:tagName",
					Actions: []string{"pull"},
				},
			},
		},
		{
			name:   "Image with port and path and tag and digest",
			scopes: "resourceType:registryName:8080/imageName:tagName@digestName:pull",
			want: []*token.ResourceActions{
				{
					Type:    "resourceType",
					Name:    "registryName:8080/imageName:tagName@digestName",
					Actions: []string{"pull"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{}
			if got := s.parseScope(tt.scopes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseScope() = %#+v, want %#+v", actionsToString(got), actionsToString(tt.want))
			}
		})
	}
}

func TestServer_sanitiseScope(t *testing.T) {
	tests := []struct {
		name             string
		isPublic         bool
		validCredentials bool
		scope            *token.ResourceActions
		want             *token.ResourceActions
	}{
		{
			name:             "InvalidAuth-NotPublic-Pull",
			isPublic:         false,
			validCredentials: false,
			scope: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"pull"},
			},
			want: nil,
		},
		{
			name:             "InvalidAuth-Public-Pull",
			isPublic:         true,
			validCredentials: false,
			scope: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"pull"},
			},
			want: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"pull"},
			},
		},
		{
			name:             "InvalidAuth-Public-Push",
			isPublic:         true,
			validCredentials: false,
			scope: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"push"},
			},
			want: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"pull"},
			},
		},
		{
			name:             "InvalidAuth-Public-PushPull",
			isPublic:         true,
			validCredentials: false,
			scope: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"push", "pull"},
			},
			want: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"pull"},
			},
		},
		{
			name:             "ValidAuth-NotPublic-Pull",
			isPublic:         false,
			validCredentials: true,
			scope: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"pull"},
			},
			want: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"pull"},
			},
		},
		{
			name:             "ValidAuth-Public-Push",
			isPublic:         false,
			validCredentials: true,
			scope: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"push"},
			},
			want: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"push"},
			},
		},
		{
			name:             "ValidAuth-Public-PushPull",
			isPublic:         false,
			validCredentials: true,
			scope: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"push", "pull"},
			},
			want: &token.ResourceActions{
				Type:    "repositoryName",
				Name:    "imageName",
				Actions: []string{"push", "pull"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{}
			if got := s.sanitiseScope(tt.scope, tt.isPublic, tt.validCredentials); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sanitiseScope() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServer_Authenticate(t *testing.T) {
	tests := []struct {
		name    string
		request *Request
		users   map[string]string
		want    bool
	}{
		{
			name:  "No users",
			users: map[string]string{},
			request: &Request{
				User:     "",
				Password: "",
			},
			want: false,
		},
		{
			name:  "Unknown user",
			users: map[string]string{"test": "$2a$07$N/0tVCSbMg.igieLxDNYyOhjJxEIHec1ia01Wgr6jNk4gZwgUUlWq"},
			request: &Request{
				User:     "test2",
				Password: "",
			},
			want: false,
		},
		{
			name:  "Know user, blank password",
			users: map[string]string{"test": "$2a$07$N/0tVCSbMg.igieLxDNYyOhjJxEIHec1ia01Wgr6jNk4gZwgUUlWq"},
			request: &Request{
				User:     "test",
				Password: "",
			},
			want: false,
		},
		{
			name:  "Know user, wrong password",
			users: map[string]string{"test": "$2a$07$N/0tVCSbMg.igieLxDNYyOhjJxEIHec1ia01Wgr6jNk4gZwgUUlWq"},
			request: &Request{
				User:     "test",
				Password: "password",
			},
			want: false,
		},
		{
			name:  "Know user, right password",
			users: map[string]string{"test": "$2a$07$N/0tVCSbMg.igieLxDNYyOhjJxEIHec1ia01Wgr6jNk4gZwgUUlWq"},
			request: &Request{
				User:     "test",
				Password: "test",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				Users: tt.users,
			}
			if got := s.Authenticate(tt.request); got != tt.want {
				t.Errorf("Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServer_isScopePublic(t *testing.T) {
	tests := []struct {
		name           string
		PublicPrefixes []string
		scopeType      string
		scopeName      string
		want           bool
	}{
		{
			name:           "",
			PublicPrefixes: []string{"public"},
			scopeType:      "registry",
			scopeName:      "catalog",
			want:           false,
		},
		{
			name:           "",
			PublicPrefixes: []string{"public"},
			scopeType:      "registry",
			scopeName:      "test",
			want:           false,
		},
		{
			name:           "",
			PublicPrefixes: []string{"public"},
			scopeType:      "repository",
			scopeName:      "test",
			want:           false,
		},
		{
			name:           "",
			PublicPrefixes: []string{"public"},
			scopeType:      "repository",
			scopeName:      "public",
			want:           false,
		},
		{
			name:           "",
			PublicPrefixes: []string{"public"},
			scopeType:      "repository",
			scopeName:      "public/",
			want:           false,
		},
		{
			name:           "",
			PublicPrefixes: []string{"public"},
			scopeType:      "repository",
			scopeName:      "public/test",
			want:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				PublicPrefixes: tt.PublicPrefixes,
			}
			if got := s.isScopePublic(&token.ResourceActions{
				Type: tt.scopeType,
				Name: tt.scopeName,
			}); got != tt.want {
				t.Errorf("isScopePublic() = %v, want %v", got, tt.want)
			}
		})
	}
}
