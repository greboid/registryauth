package auth

import (
	"reflect"
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
						Type:    "",
						Class:   "",
						Name:    "test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: true,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Type:    "",
					Class:   "",
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
						Type:    "",
						Class:   "",
						Name:    "test",
						Actions: []string{"push", "pull"},
					},
				},
				validCredentials: false,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Type:    "",
					Class:   "",
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
						Type:    "",
						Class:   "",
						Name:    "test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: false,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Type:    "",
					Class:   "",
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
						Type:    "",
						Class:   "",
						Name:    "test",
						Actions: []string{"pull"},
					},
				},
				validCredentials: true,
			},
			wantApprovedScopes: []*token.ResourceActions{
				{
					Type:    "",
					Class:   "",
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
						Type:    "",
						Class:   "",
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
				t.Errorf("Authorize() gotApprovedScopes = %#v, want %#v", gotApprovedScopes, tt.wantApprovedScopes)
			}
		})
	}
}
