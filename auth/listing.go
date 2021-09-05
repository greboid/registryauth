package auth

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

var (
	ShowIndex    = flag.Bool("show-index", false, "Show an index page, rather than just a 200 response")
	ShowListings = flag.Bool("show-listings", true, "Index page lists public repositories")
	PullHostname = flag.String("pull-hostname", "", "Hostname to show on listings and info page, will default to the request hostname")
	RegistryHost = flag.String("registry-host", "http://localhost:8080", "The URL of the registry being listed")
)

type Lister struct {
	templates      *template.Template
	TokenProvider  TokenProvider
	PublicPrefixes []string
}

type TokenProvider func(...string) (string, error)

type RepositoryList struct {
	Repositories []*Repository
}

type Repository struct {
	Name string
	Tags []string
}

type Catalog struct {
	Repositories []string `json:"repositories"`
}

type ListingIndex struct {
	Title        string
	Repositories *RepositoryList
}

type Index struct {
	Title string
}

func (s *Lister) Initialise(router *mux.Router) {
	s.templates = template.Must(template.New("").
		Funcs(template.FuncMap{
			"TagPrint": func(input []string) string {
				if len(input) == 0 {
					return "No Tags"
				}
				return strings.Join(input, ", ")
			},
		}).
		ParseFS(templates, "templates/*.gohtml", "templates/*.css"))
	if *ShowListings {
		router.Path("/").HandlerFunc(s.ListingIndex)
		router.Path("/css").HandlerFunc(s.CSS)
	} else if *ShowIndex {
		router.Path("/").HandlerFunc(s.Index)
		router.Path("/css").HandlerFunc(s.CSS)
	} else {
		router.Path("/").HandlerFunc(s.OK)
	}
}

func (s *Lister) CSS(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Add("Content-Type", "text/css")
	err := s.templates.ExecuteTemplate(writer, "normalize.css", nil)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = s.templates.ExecuteTemplate(writer, "main.css", nil)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Lister) OK(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func (s *Lister) Index(writer http.ResponseWriter, req *http.Request) {
	err := s.templates.ExecuteTemplate(writer, "index.gohtml", Index{
		Title: s.getHostname(req),
	})
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Lister) ListingIndex(writer http.ResponseWriter, req *http.Request) {
	publicRepositories, err := s.getCatalog()
	_, err = s.getRepoInfo("moo")
	if err != nil {
		log.Printf("Error: %s", err)
		return
	}
	repositoryList := &RepositoryList{}
	for index := range publicRepositories {
		repoInfo, err := s.getRepoInfo(publicRepositories[index])
		if err == nil {
			repositoryList.Repositories = append(repositoryList.Repositories, repoInfo)
		}
	}
	err = s.templates.ExecuteTemplate(writer, "listingIndex.gohtml", ListingIndex{
		Title:        s.getHostname(req),
		Repositories: repositoryList,
	})
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Lister) getRepoInfo(repository string) (*Repository, error) {
	accessToken, err := s.TokenProvider(repository)
	if err != nil {
		return nil, errors.New("error obtaining access token")
	}
	httpClient := http.Client{}
	getRequest, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v2/%s/tags/list", *RegistryHost, repository), nil)
	if err != nil {
		return nil, errors.New("error creating request")
	}
	getRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := httpClient.Do(getRequest)
	if err != nil {
		return nil, errors.New("unable to perform request")
	}
	listBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("unable to read body")
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	list := &Repository{}
	err = json.Unmarshal(listBody, list)
	if err != nil {
		return nil, errors.New("unable to unmarshall response")
	}
	list.Name = repository
	return list, nil
}

func (s *Lister) getCatalog() ([]string, error) {
	accessToken, err := s.TokenProvider()
	if err != nil {
		return nil, errors.New("error obtaining access token")
	}
	httpClient := http.Client{}
	getRequest, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v2/_catalog", *RegistryHost), nil)
	if err != nil {
		return nil, errors.New("error creating request")
	}
	getRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := httpClient.Do(getRequest)
	if err != nil {
		return nil, errors.New("unable to perform request")
	}
	listBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("unable to read body")
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	list := &Catalog{}
	err = json.Unmarshal(listBody, list)
	if err != nil {
		return nil, errors.New("unable to unmarshall response")
	}
	var publicRepositories []string
	for index := range list.Repositories {
		if isScopePublic(s.PublicPrefixes, &token.ResourceActions{
			Type:    "repository",
			Name:    list.Repositories[index],
			Actions: []string{"pull"},
		}) {
			publicRepositories = append(publicRepositories, list.Repositories[index])
		}
	}
	return publicRepositories, nil
}

func (s *Lister) getHostname(req *http.Request) string {
	if *PullHostname != "" {
		return *PullHostname
	} else if req != nil && req.Host != "" {
		return req.Host
	}
	return "Docker Registry"
}
