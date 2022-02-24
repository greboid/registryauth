package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
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
	config := getSharedConfig(directory)
	config.Auth = configuration.Auth{
		"token": {
			"autoredirect":   true,
			"realm":          realm,
			"issuer":         issuer,
			"service":        service,
			"rootcertbundle": cert,
		},
	}
	config.Notifications = configuration.Notifications{
		Endpoints: getNotifyEndpoints(notifyEndpoint, notifyToken),
	}
	return handlers.NewApp(dcontext.WithVersion(dcontext.Background(), version.Version), config)
}

func getSharedConfig(directory string) *configuration.Configuration {
	config := &configuration.Configuration{
		Storage: configuration.Storage{
			"filesystem": configuration.Parameters{
				"rootdirectory": directory,
			},
			"delete": configuration.Parameters{
				"enabled": true,
			},
		},
	}
	config.HTTP.Secret = fmt.Sprintf("%d", rand.Int63())
	return config
}

func getNotifyEndpoints(endpoints string, tokens string) []configuration.Endpoint {
	var result = []configuration.Endpoint{}
	if strings.TrimSpace(endpoints) == "" || strings.TrimSpace(tokens) == "" {
		return result
	}
	var parsedEnpoints, parsedTokens []string
	if !strings.Contains(endpoints, ",") && !strings.Contains(tokens, ",") {
		parsedEnpoints = []string{endpoints}
		parsedTokens = []string{tokens}
	} else {
		parsedEnpoints = strings.Split(endpoints, ",")
		parsedTokens = strings.Split(tokens, ",")
		if len(parsedEnpoints) != len(parsedTokens) {
			return []configuration.Endpoint{}
		}
	}
	for index := range parsedEnpoints {
		if strings.TrimSpace(parsedEnpoints[index]) == "" || strings.TrimSpace(parsedTokens[index]) == "" {
			continue
		}
		_, err := url.Parse(parsedEnpoints[index])
		if err != nil {
			continue
		}
		result = append(result, configuration.Endpoint{
			Name:      fmt.Sprintf("notify%d", index),
			Disabled:  false,
			URL:       strings.TrimSpace(parsedEnpoints[index]),
			Headers:   http.Header{"Authorization": []string{"Bearer " + strings.TrimSpace(parsedTokens[index])}},
			Timeout:   1 * time.Second,
			Threshold: 5,
			Backoff:   5 * time.Second,
		})
	}
	return result
}
