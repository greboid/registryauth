package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	dcontext "github.com/distribution/distribution/v3/context"
	_ "github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/distribution/distribution/v3/registry/handlers"
	_ "github.com/distribution/distribution/v3/registry/proxy"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/distribution/v3/version"
	_ "github.com/spf13/cobra"
)

func StartRegistry(directory, realm, issuer, service, cert, notifyEndpoint, notifyToken string) http.Handler {
	config := &configuration.Configuration{
		Storage: configuration.Storage{
			"filesystem": configuration.Parameters{
				"rootdirectory": directory,
			},
			"delete": configuration.Parameters{
				"enable": true,
			},
		},
		Auth: configuration.Auth{
			"token": {
				"autoredirect":   true,
				"realm":          realm,
				"issuer":         issuer,
				"service":        service,
				"rootcertbundle": cert,
			},
		},
		Notifications: configuration.Notifications{
			Endpoints: getNotifyEndpoint(notifyEndpoint, notifyToken),
		},
	}
	config.HTTP.Secret = fmt.Sprintf("%d", rand.Int63())
	return handlers.NewApp(dcontext.WithVersion(dcontext.Background(), version.Version), config)
}

func getNotifyEndpoint(endpoint string, token string) []configuration.Endpoint {
	if endpoint == "" {
		return []configuration.Endpoint{}
	}
	_, err := url.Parse(endpoint)
	if err != nil {
		return []configuration.Endpoint{}
	}
	return []configuration.Endpoint{
		{
			Name:      "notify",
			Disabled:  false,
			URL:       endpoint,
			Headers:   http.Header{"Authorization": []string{"Bearer " + token}},
			Timeout:   1 * time.Second,
			Threshold: 5,
			Backoff:   5 * time.Second,
		},
	}
}
