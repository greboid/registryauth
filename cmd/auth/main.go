package main

import (
	"flag"
	"path/filepath"

	"github.com/csmith/envflag"
	"github.com/gorilla/mux"
	"github.com/greboid/registryauth/auth"
	"github.com/greboid/registryauth/certs"
	"github.com/greboid/registryauth/listing"
	log "github.com/sirupsen/logrus"
)

var (
	dataDirectory = flag.String("data-dir", filepath.Join(".", "data"), "Data directory")
	certPath      = ""
	keyPath       = ""
	RegistryHost  = flag.String("registry-host", "http://localhost:8080", "The URL of the registry being listed")
)

func main() {
	envflag.Parse()
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
	log.Infof("Server started")
	err = authServer.StartAndWait()
	if err != nil {
		log.Infof("Server ended: %s", err)
	} else {
		log.Infof("server ended")
	}
}
