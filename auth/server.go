package auth

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/docker/libtrust"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/greboid/registryauth/certs"
	"gopkg.in/yaml.v2"
)

var (
	ServerPort = flag.Int("port", 8080, "Port for the server to listen on")
)

type Server struct {
	publicKey      libtrust.PublicKey
	privateKey     libtrust.PrivateKey
	Users          map[string]string
	PublicPrefixes []string
	Issuer         string
	CertDir        string
	CertPath       string
	KeyPath        string
	Service        string
	Realm          string
	Port           int
	Debug          bool
	Router         *mux.Router
	ShowIndex      bool
	ShowListing    bool
	templates      *template.Template
	PullHostname   string
}

//go:embed templates
var templates embed.FS

func (s *Server) Initialise() error {
	err := certs.GenerateSelfSignedCert(s.CertPath, s.KeyPath)
	if err != nil {
		return fmt.Errorf("generating certificates: %s", err.Error())
	}
	err = s.LoadCertAndKey(s.CertPath, s.KeyPath)
	if err != nil {
		return fmt.Errorf("loading certicates: %s", err.Error())
	}
	s.templates = template.Must(template.ParseFS(templates, "templates/*.gohtml", "templates/*.css"))
	if s.ShowListing {
		s.Router.Path("/").HandlerFunc(s.ListingIndex)
		s.Router.Path("/css").HandlerFunc(s.CSS)
	} else if s.ShowIndex {
		s.Router.Path("/").HandlerFunc(s.Index)
		s.Router.Path("/css").HandlerFunc(s.CSS)
	} else {
		s.Router.Path("/").HandlerFunc(s.OK)
	}
	s.Router.PathPrefix("/auth").HandlerFunc(s.HandleAuth).Methods(http.MethodPost, http.MethodGet)
	return nil
}

func (s *Server) StartAndWait() error {
	panicHandler := handlers.RecoveryHandler(handlers.PrintRecoveryStack(s.Debug))
	server := http.Server{
		Addr:    fmt.Sprintf(":%d", s.Port),
		Handler: panicHandler(s.Router),
	}
	go func() {
		_ = server.ListenAndServe()
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, os.Kill)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Server) OK(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func ParsePrefixes(prefixInput string) []string {
	var prefixList []string
	for _, prefix := range strings.Split(prefixInput, ",") {
		prefixList = append(prefixList, prefix)
	}
	return prefixList
}

func ParseUsers(userInput string) (map[string]string, error) {
	userList := map[string]string{}
	err := yaml.Unmarshal([]byte(userInput), userList)
	if err != nil {
		return nil, err
	}
	return userList, nil
}
