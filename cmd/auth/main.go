package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/greboid/registryauth/auth"
	"github.com/greboid/registryauth/certs"
	"github.com/greboid/registryauth/registry"
	"github.com/kouhin/envflag"
	"gopkg.in/yaml.v2"
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
	userList, err := parseUsers(*userInput)
	if err != nil {
		log.Fatalf("Unable to parse users: %s", err.Error())
	}
	prefixList, err := parsePrefixes(*publicPrefixes)
	if err != nil {
		log.Fatalf("Unable to parse prefixes %s", err.Error())
	}
	err = certs.GenerateSelfSignedCert("./data/certs")
	if err != nil {
		log.Fatalf("Unable to generate certificates %s", err.Error())
	}
	authServer := &auth.Server{
		Users:          userList,
		PublicPrefixes: prefixList,
		Issuer:         *issuer,
	}
	err = authServer.LoadCertAndKey(certPath, keyPath)
	if err != nil {
		log.Fatalf("Unable to parse flags: %s", err.Error())
	}
	log.Print("Starting server.")
	startAndWait(getRoutes(authServer))
	log.Print("Finishing server.")
}

func parsePrefixes(prefixInput string) ([]string, error) {
	var prefixList []string
	for _, prefix := range strings.Split(prefixInput, ",") {
		prefixList = append(prefixList, prefix)
	}
	return prefixList, nil
}

func parseUsers(userInput string) (map[string]string, error) {
	userList := map[string]string{}
	err := yaml.Unmarshal([]byte(userInput), userList)
	if err != nil {
		return nil, err
	}
	return userList, nil
}

func getRoutes(server *auth.Server) *mux.Router {
	router := mux.NewRouter()
	router.PathPrefix("/auth").HandlerFunc(server.HandleAuth).Methods(http.MethodPost, http.MethodGet)
	router.PathPrefix("/").Handler(registry.StartRegistry(*registryDirectory, *realm, *issuer, *service, certPath))
	return router
}

func startAndWait(router *mux.Router) {
	server := http.Server{
		Addr:    fmt.Sprintf(":%d", *serverPort),
		Handler: handlers.RecoveryHandler()(router),
	}
	go func() {
		_ = server.ListenAndServeTLS(certPath, keyPath)
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, os.Kill)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Unable to shutdown: %s", err.Error())
	}
}
