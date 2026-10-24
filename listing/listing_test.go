package listing

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
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
