package auth

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/distribution/distribution/v3/registry/auth/token"
)

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
						Name:    "test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: true,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Name:    "test",
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
						Name:    "test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: true,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Name:    "test",
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
						Name:    "test",
						Actions: []string{"push", "pull"},
					},
				},
				validCredentials: false,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Name:    "test",
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
						Name:    "test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: false,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Name:    "test",
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
						Name:    "test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: true,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Name:    "test",
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
						Name:    "test",
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

func actionsToString(a []*token.ResourceActions) string {
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
