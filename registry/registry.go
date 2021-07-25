package registry

import (
	"fmt"
	"github.com/distribution/distribution/v3/configuration"
	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/health"
	_ "github.com/distribution/distribution/v3/registry/auth/htpasswd"
	_ "github.com/distribution/distribution/v3/registry/auth/silly"
	_ "github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/distribution/distribution/v3/registry/handlers"
	_ "github.com/distribution/distribution/v3/registry/proxy"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/azure"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/gcs"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/middleware/alicdn"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/middleware/cloudfront"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/middleware/redirect"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/oss"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/s3-aws"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/swift"
	"github.com/distribution/distribution/v3/version"
	_ "github.com/spf13/cobra"
	"net/http"
	"os"
)

func StartRegistry(configPath string) http.Handler {
	ctx := dcontext.WithVersion(dcontext.Background(), version.Version)

	config, err := resolveConfiguration([]string{configPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}
	app := handlers.NewApp(ctx, config)
	app.RegisterHealthChecks()
	return health.Handler(app)
}

func resolveConfiguration(args []string) (*configuration.Configuration, error) {
	var configurationPath string

	if len(args) > 0 {
		configurationPath = args[0]
	} else if os.Getenv("REGISTRY_CONFIGURATION_PATH") != "" {
		configurationPath = os.Getenv("REGISTRY_CONFIGURATION_PATH")
	}

	if configurationPath == "" {
		return nil, fmt.Errorf("configuration path unspecified")
	}

	fp, err := os.Open(configurationPath)
	if err != nil {
		return nil, err
	}

	defer fp.Close()

	config, err := configuration.Parse(fp)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s: %v", configurationPath, err)
	}

	return config, nil
}