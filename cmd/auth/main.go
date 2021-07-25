package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/greboid/registryauth/certs"
	"github.com/greboid/registryauth/registry"
	"github.com/kouhin/envflag"
)

type customClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	err := envflag.Parse()
	if err != nil {
		log.Fatalf("Unable to parse flags: %s", err.Error())
	}
	err = certs.GenerateSelfSignedCert("./data/certs")
	if err != nil {
		log.Fatalf("Unable to parse flags: %s", err.Error())
	}
	log.Print("Starting server.")
	startAndWait(getRoutes())
	log.Print("Finishing server.")
}

type AuthResponse struct {
	Token string `json:"token"`
}

func getRoutes() *mux.Router {
	router := mux.NewRouter()
	router.PathPrefix("/v2/token").HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
	})
	router.PathPrefix("/v2/auth").HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
	})
	router.PathPrefix("/auth").HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
	})
	router.PathPrefix("/").Handler(registry.StartRegistry("./registry-config.yml"))
	return router
}

func startAndWait(router *mux.Router) {
	server := http.Server{
		Addr:    ":8080",
		Handler: logger(router),
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
		log.Printf("Body\n%s\n", body)
		next.ServeHTTP(writer, request)
	})
}
