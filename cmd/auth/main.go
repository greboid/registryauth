package main

import (
	"flag"
	"path/filepath"

	"github.com/csmith/envflag/v2"
	"github.com/gorilla/mux"
	"github.com/greboid/registryauth/auth"
	"github.com/greboid/registryauth/certs"
	"github.com/greboid/registryauth/listing"
	"github.com/greboid/registryauth/login"
	log "github.com/sirupsen/logrus"
)

var (
	dataDirectory = flag.String("data-dir", filepath.Join(".", "data"), "Data directory")
	certPath      = ""
	keyPath       = ""
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
	authenticator, err := login.New(login.Config{
		Issuer:       *login.Issuer,
		ClientID:     *login.ClientID,
		ClientSecret: *login.ClientSecret,
		ExternalURL:  *login.ExternalURL,
		Group:        *login.Group,
		RequireLogin: *login.RequireLogin,
	})
	if err != nil {
		log.Fatalf("Unable to configure login: %s", err)
	}
	lister := listing.NewLister(authServer.PublicPrefixes, authServer.GetFullAccessToken)
	if authenticator != nil {
		// Must be routed before the lister's catch-all repository route.
		authenticator.AddRoutes(authServer.Router)
		lister.Login = authenticator
	}
	lister.Initialise(authServer.Router)
	log.Infof("Server started")
	err = authServer.StartAndWait()
	if err != nil {
		log.Infof("Server ended: %s", err)
	} else {
		log.Infof("server ended")
	}
}
