package main

import (
	"flag"
	"path/filepath"

	"github.com/csmith/envflag"
	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/registry/storage"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	"github.com/docker/libtrust"
	"github.com/gorilla/mux"
	"github.com/greboid/registryauth/auth"
	"github.com/greboid/registryauth/certs"
	"github.com/greboid/registryauth/listing"
	log "github.com/sirupsen/logrus"
)

var (
	dataDirectory     = flag.String("data-dir", filepath.Join(".", "data"), "Data directory")
	registryDirectory = flag.String("registry-dir", filepath.Join(*dataDirectory, "registry"), "Registry data directory")
	notifyEndpoint    = flag.String("notify-endpoint", "", "URL that receives registry notifications")
	notifyToken       = flag.String("notify-token", "", "Bearer token to send with registry notifications")
	certPath          = ""
	keyPath           = ""
	GC                = flag.Bool("gc", false, "Run GC on the registry, ensure no other instances are running or are read only.")
	dryRun            = flag.Bool("dry-run", false, "Perform a dry run of the GC")
	RegistryHost      = flag.String("registry-host", "http://localhost:8080", "The URL of the registry being listed")
)

func main() {
	envflag.Parse()
	if *GC {
		log.Infof("Starting GC")
		runGC()
	} else {
		log.Infof("Starting registry")
		runReg()
	}
}

func runGC() {
	config := getSharedConfig(*registryDirectory, *RegistryHost)
	driver, err := factory.Create(config.Storage.Type(), config.Storage.Parameters())
	if err != nil {
		log.Fatalf("failed to construct %s driver: %v", config.Storage.Type(), err)
	}
	ctx := dcontext.Background()
	auth.InitFormatter()
	k, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		log.Fatalf("error generating key: %s", err)
	}
	registry, err := storage.NewRegistry(ctx, driver, storage.Schema1SigningKey(k))
	if err != nil {
		log.Fatalf("failed to construct registry: %v", err)
	}
	err = storage.MarkAndSweep(ctx, driver, registry, storage.GCOpts{
		DryRun:         *dryRun,
		RemoveUntagged: true,
	})
	if err != nil {
		log.Fatalf("failed to garbage collect: %v", err)
	}
}

func runReg() {
	certPath, keyPath = certs.GetCertPaths(*dataDirectory)
	auth.InitFormatter()
	users, err := auth.ParseUsers(*auth.UserInput)
	if err != nil {
		log.Fatalf("Unable to parse users: %s", err)
	}
	authServer := &auth.Server{
		Users:          users,
		PublicPrefixes: auth.ParsePrefixes(*auth.PublicPrefixes),
		Issuer:         *auth.Issuer,
		Realm:          *auth.Realm,
		Service:        *auth.Service,
		CertPath:       certPath,
		KeyPath:        keyPath,
		Port:           *auth.ServerPort,
		Debug:          *auth.Debug,
		Router:         mux.NewRouter(),
	}
	err = authServer.Initialise()
	if err != nil {
		log.Fatalf("Unable to %s", err.Error())
	}
	lister := listing.NewLister(*RegistryHost, authServer.PublicPrefixes, authServer.GetFullAccessToken)
	lister.Initialise(authServer.Router)
	authServer.Router.PathPrefix("/").Handler(StartRegistry(*registryDirectory, *auth.Realm, *auth.Issuer, *auth.Service, certPath, *RegistryHost, *notifyEndpoint, *notifyToken))
	log.Infof("Server started")
	err = authServer.StartAndWait()
	if err != nil {
		log.Infof("Server ended: %s", err)
	} else {
		log.Infof("server ended")
	}
}
