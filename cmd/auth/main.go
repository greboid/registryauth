package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	publicPrefixes = flag.String("public", "", "prefixes of public readable folders")
	userInput      = flag.String("users", "", "Yaml formatted list of users")
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
	}
	err = authServer.LoadCertAndKey("./data/certs/cert.pem", "./data/certs/key.pem")
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
	router.PathPrefix("/").Handler(registry.StartRegistry("./registry-config.yml"))
	return router
}

func startAndWait(router *mux.Router) {
	server := http.Server{
		Addr:    ":8080",
		Handler: handlers.RecoveryHandler()(logger(router)),
	}
	go func() {
		_ = server.ListenAndServeTLS("./data/certs/cert.pem", "./data/certs/key.pem")
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

func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() { _ = request.Body.Close() }()
		body, _ := io.ReadAll(request.Body)
		log.Printf("Method: %s", request.Method)
		log.Printf("URL: %s", request.URL)
		log.Printf("Headers: %+v", request.Header)
		if len(body) < 100 {
			log.Printf("Body\n%s\n", body)
		} else {
			log.Printf("Body: Large body provided")
		}
		next.ServeHTTP(writer, request)
	})
}
