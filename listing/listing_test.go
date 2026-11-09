package listing

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"
)

func TestListingIndexAvailability(t *testing.T) {
	lister := NewLister(nil, nil)
	lister.getTemplates()

	writer := httptest.NewRecorder()
	lister.ListingIndex(writer, httptest.NewRequest(http.MethodGet, "/", nil))
	if writer.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 before first snapshot, got %d", writer.Code)
	}

	lister.storeSnapshot(&RepositoryList{})
	writer = httptest.NewRecorder()
	lister.ListingIndex(writer, httptest.NewRequest(http.MethodGet, "/", nil))
	if writer.Code != http.StatusOK {
		t.Errorf("expected 200 after snapshot, got %d", writer.Code)
	}
}

func TestLister_RepositoryDetails(t *testing.T) {
	lister := NewLister(nil, nil)
	lister.getTemplates()

	writer := httptest.NewRecorder()
	lister.RepositoryDetails(writer, httptest.NewRequest(http.MethodGet, "/public/test", nil))
	if writer.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 before first snapshot, got %d", writer.Code)
	}

	lister.storeSnapshot(&RepositoryList{Repositories: []*Repository{
		{Name: "public/test", Tags: []Tag{{Name: "v1.2.3", SHA: "sha256:deadbeef", Size: 1234}}},
		{Name: "public/empty"},
	}})

	tests := []struct {
		name         string
		path         string
		wantCode     int
		wantContains string
	}{
		{
			name:         "Repository with tags",
			path:         "/public/test",
			wantCode:     http.StatusOK,
			wantContains: "sha256:deadbeef",
		},
		{
			name:         "Trailing slash",
			path:         "/public/test/",
			wantCode:     http.StatusOK,
			wantContains: "v1.2.3",
		},
		{
			name:         "Repository without tags",
			path:         "/public/empty",
			wantCode:     http.StatusOK,
			wantContains: "No Tags",
		},
		{
			name:     "Partial name",
			path:     "/public",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Unknown repository",
			path:     "/private/test",
			wantCode: http.StatusNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := httptest.NewRecorder()
			lister.RepositoryDetails(writer, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if writer.Code != tt.wantCode {
				t.Errorf("RepositoryDetails() code = %v, want %v", writer.Code, tt.wantCode)
			}
			if !strings.Contains(writer.Body.String(), tt.wantContains) {
				t.Errorf("RepositoryDetails() body = %q, want to contain %q", writer.Body.String(), tt.wantContains)
			}
		})
	}
}

func TestLister_repositoryDetailsDoesNotShadowRoutes(t *testing.T) {
	lister := NewLister(nil, func(...string) (string, error) {
		return "", errors.New("no token")
	})
	router := mux.NewRouter()
	lister.Initialise(router)

	tests := []struct {
		name     string
		path     string
		wantCode int
	}{
		{
			name:     "CSS",
			path:     "/css",
			wantCode: http.StatusOK,
		},
		{
			name:     "JS",
			path:     "/js",
			wantCode: http.StatusOK,
		},
		{
			name:     "Repository",
			path:     "/public/test",
			wantCode: http.StatusServiceUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := httptest.NewRecorder()
			router.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if writer.Code != tt.wantCode {
				t.Errorf("ServeHTTP() code = %v, want %v", writer.Code, tt.wantCode)
			}
		})
	}
}

func TestListingIndexConcurrentRefreshAndRender(t *testing.T) {
	lister := NewLister([]string{"public"}, nil)
	lister.getTemplates()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 200 {
			lister.storeSnapshot(&RepositoryList{Repositories: []*Repository{{
				Name: "public/test",
				Tags: []Tag{{Name: "latest", SHA: "sha256:deadbeef", Size: 1234}},
			}}})
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			writer := httptest.NewRecorder()
			lister.ListingIndex(writer, httptest.NewRequest(http.MethodGet, "/", nil))
		}
	}()
	wg.Wait()
}
