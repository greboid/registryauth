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
	log "github.com/sirupsen/logrus"
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
	//log.SetLevel(log.ErrorLevel)
	log.SetFormatter(Formatter{})
	return handlers.NewApp(dcontext.WithVersion(dcontext.Background(), version.Version), config)
}

type Formatter struct{}

func (f Formatter) Format(entry *log.Entry) ([]byte, error) {
	return []byte(fmt.Sprintf("%s %s: %s\n", entry.Time.Format("2006/01/02 15:04:05"), entry.Level, entry.Message)), nil
}
