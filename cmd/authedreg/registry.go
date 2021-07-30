package main

import (
	"fmt"
	"math/rand"
	"net/http"

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

func StartRegistry(directory string, realm string, issuer string, service string, cert string) http.Handler {
	config := &configuration.Configuration{
		Storage: configuration.Storage{
			"filesystem": configuration.Parameters{
				"rootdirectory": directory,
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
	}
	config.HTTP.Secret = fmt.Sprintf("%d", rand.Int63())
	return handlers.NewApp(dcontext.WithVersion(dcontext.Background(), version.Version), config)
}
