package main

import (
	"flag"
	"log"
	"path/filepath"

	"github.com/gorilla/mux"
	"github.com/greboid/registryauth/auth"
	"github.com/kouhin/envflag"
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
	certPath          = filepath.Join(*certDirectory, "cert.pem")
	keyPath           = filepath.Join(*certDirectory, "key.pem")
)

func main() {
	err := envflag.Parse()
	if err != nil {
		log.Fatalf("Unable to parse flags: %s", err.Error())
	}
	authServer := &auth.Server{
		Users:          auth.ParseUsers(*userInput),
		PublicPrefixes: auth.ParsePrefixes(*publicPrefixes),
		Issuer:         *issuer,
		Realm:          *realm,
		Service:        *service,
		CertPath:       certPath,
		KeyPath:        keyPath,
		Port:           *serverPort,
		Router:         mux.NewRouter(),
	}
	err = authServer.Initialise()
	if err != nil {
		log.Fatalf("Unable to %s", err.Error())
	}
	authServer.Router.PathPrefix("/").Handler(StartRegistry(*registryDirectory, *realm, *issuer, *service, certPath))
	log.Print("Starting server.")
	authServer.StartAndWait()
	log.Print("Finishing server.")
}
