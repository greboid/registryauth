package main

import (
	"flag"
	"path/filepath"

	"github.com/gorilla/mux"
	"github.com/greboid/registryauth/auth"
	"github.com/kouhin/envflag"
	log "github.com/sirupsen/logrus"
)

var (
	publicPrefixes    = flag.String("public", "", "prefixes of public readable folders")
	userInput         = flag.String("users", "", "Yaml formatted list of users")
	serverPort        = flag.Int("port", 8080, "Port for the server to listen on")
	realm             = flag.String("realm", "Registry", "Realm for the registry")
	issuer            = flag.String("issuer", "Registry", "Issuer for the registry")
	service           = flag.String("service", "Registry", "Service name for the registry")
	dataDirectory     = flag.String("data-dir", filepath.Join(".", "data"), "Data directory")
	registryDirectory = flag.String("registry-dir", filepath.Join(*dataDirectory, "registry"), "Registry data directory")
	certDirectory     = flag.String("cert-dir", filepath.Join(*dataDirectory, "certs"), "Certificate directory")
	debug             = flag.Bool("debug", false, "Show debug logging")
	certPath          = filepath.Join(*certDirectory, "cert.pem")
	keyPath           = filepath.Join(*certDirectory, "key.pem")
)

func main() {
	err := envflag.Parse()
	if err != nil {
		log.Fatalf("Unable to parse flags: %s", err.Error())
	}
	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.ErrorLevel)
	}
	log.SetFormatter(auth.Formatter{Debug: *debug})
	users, err := auth.ParseUsers(*userInput)
	if err != nil {
		log.Fatalf("Unable to parse users: %s", err)
	}
	authServer := &auth.Server{
		Users:          users,
		PublicPrefixes: auth.ParsePrefixes(*publicPrefixes),
		Issuer:         *issuer,
		Realm:          *realm,
		Service:        *service,
		CertPath:       certPath,
		KeyPath:        keyPath,
		Port:           *serverPort,
		Debug:          *debug,
		Router:         mux.NewRouter(),
	}
	err = authServer.Initialise()
	if err != nil {
		log.Fatalf("Unable to %s", err.Error())
	}
	authServer.Router.PathPrefix("/").Handler(StartRegistry(*registryDirectory, *realm, *issuer, *service, certPath))
	log.Infof("Server started")
	err = authServer.StartAndWait()
	if err != nil {
		log.Infof("Server ended: %s", err)
	} else {
		log.Infof("server ended")
	}
}
