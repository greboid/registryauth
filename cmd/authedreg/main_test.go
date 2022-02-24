package main

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/configuration"
)

func Test_getEndpoints(t *testing.T) {
	tests := []struct {
		name      string
		endpoints string
		tokens    string
		want      []configuration.Endpoint
	}{
		{
			name:      "Empty",
			endpoints: "",
			tokens:    "",
			want:      []configuration.Endpoint{},
		},
		{
			name:      "Single endpoint, no token",
			endpoints: "endpoint1",
			tokens:    "",
			want:      []configuration.Endpoint{},
		},
		{
			name:      "no endpoint, single token",
			endpoints: "endpoint1",
			tokens:    "",
			want:      []configuration.Endpoint{},
		},
		{
			name:      "Single endpoint, single token",
			endpoints: "endpoint1",
			tokens:    "token1",
			want: []configuration.Endpoint{
				{
					Name:      "notify0",
					URL:       "endpoint1",
					Headers:   http.Header{"Authorization": []string{"Bearer " + "token1"}},
					Timeout:   1 * time.Second,
					Threshold: 5,
					Backoff:   5 * time.Second,
				},
			},
		},
		{
			name:      "Two endpoints, single token",
			endpoints: "endpoint1, endpoint2",
			tokens:    "token1",
			want:      []configuration.Endpoint{},
		},
		{
			name:      "two endpoints, two tokens",
			endpoints: "endpoint1, endpoint2",
			tokens:    "token1, token2",
			want: []configuration.Endpoint{
				{
					Name:      "notify0",
					URL:       "endpoint1",
					Headers:   http.Header{"Authorization": []string{"Bearer " + "token1"}},
					Timeout:   1 * time.Second,
					Threshold: 5,
					Backoff:   5 * time.Second,
				},
				{
					Name:      "notify1",
					URL:       "endpoint2",
					Headers:   http.Header{"Authorization": []string{"Bearer " + "token2"}},
					Timeout:   1 * time.Second,
					Threshold: 5,
					Backoff:   5 * time.Second,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getNotifyEndpoints(tt.endpoints, tt.tokens)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getEndpoints() got = %v, want %v", got, tt.want)
			}
		})
	}
}
