package main

import (
	"flag"
	"path/filepath"

	"github.com/gorilla/mux"
	"github.com/greboid/registryauth/auth"
	"github.com/greboid/registryauth/certs"
	"github.com/kouhin/envflag"
	log "github.com/sirupsen/logrus"
)

var (
	dataDirectory     = flag.String("data-dir", filepath.Join(".", "data"), "Data directory")
	registryDirectory = flag.String("registry-dir", filepath.Join(*dataDirectory, "registry"), "Registry data directory")
	notifyEndpoint    = flag.String("notify-endpoint", "", "URL that receives registry notifications")
	notifyToken       = flag.String("notify-token", "", "Bearer token to send with registry notifications")
	certPath          = ""
	keyPath           = ""
)

func main() {
	if err := envflag.Parse(); err != nil {
		log.Fatalf("Unable to parse flags: %s", err.Error())
	}
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
		PullHostname:   *auth.PullHostname,
		ShowIndex:      *auth.ShowIndex,
		ShowListing:    *auth.ShowListings,
	}
	err = authServer.Initialise()
	if err != nil {
		log.Fatalf("Unable to %s", err.Error())
	}
	authServer.Router.PathPrefix("/").Handler(StartRegistry(*registryDirectory, *auth.Realm, *auth.Issuer, *auth.Service, certPath, *notifyEndpoint, *notifyToken))
	log.Infof("Server started")
	err = authServer.StartAndWait()
	if err != nil {
		log.Infof("Server ended: %s", err)
	} else {
		log.Infof("server ended")
	}
}
