package auth

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

var (
	ShowIndex       = flag.Bool("show-index", false, "Show an index page, rather than just a 200 response")
	ShowListings    = flag.Bool("show-listings", true, "Index page lists public repositories")
	PullHostname    = flag.String("pull-hostname", "", "Hostname to show on listings and info page, will default to the request hostname")
	RegistryHost    = flag.String("registry-host", "http://localhost:8080", "The URL of the registry being listed")
	RefreshInterval = flag.Duration("refresh-interval", 60*time.Second, "The time between registry refreshes")
)

type Lister struct {
	templates      *template.Template
	TokenProvider  TokenProvider
	PublicPrefixes []string
	repositories   *RepositoryList
	lastPoll       time.Time
}

type TokenProvider func(...string) (string, error)

type RepositoryList struct {
	Repositories []*Repository
}

type DistributionRepository struct {
	Name string
	Tags []string
}

type Repository struct {
	Name string
	Tags []Tag
}

type Tag struct {
	Name string
	SHA  string
}

type Catalog struct {
	Repositories []string `json:"repositories"`
}

type ListingIndex struct {
	Title        string
	Repositories *RepositoryList
	LastPolled   time.Time
}

type Index struct {
	Title string
}

func (s *Lister) Initialise(router *mux.Router) {
	s.templates = template.Must(template.New("").
		Funcs(template.FuncMap{
			"TagPrint": func(input []Tag) string {
				if len(input) == 0 {
					return "No Tags"
				}
				output := ""
				for index := range input {
					if index != 0 {
						output += ", "
					}
					output += input[index].Name
				}
				return output
			},
			"SHAPrint": func(input []Tag) string {
				if len(input) == 0 {
					return "No Tags"
				}
				output := ""
				for index := range input {
					if index != 0 {
						output += ", "
					}
					output += input[index].Name + " (" + input[index].SHA + ")"
				}
				return output
			},
			"DisplayTime": func(format time.Time) string {
				return format.Format("02-01 15:04")
			},
		}).
		ParseFS(templates, "templates/*.gohtml", "templates/*.css", "templates/*.js"))
	if *ShowListings {
		log.Infof("Enabling listings")
		router.Path("/").HandlerFunc(s.ListingIndex)
		router.Path("/css").HandlerFunc(s.CSS)
		router.Path("/js").HandlerFunc(s.JS)
		s.start()
	} else if *ShowIndex {
		log.Infof("Showing index only")
		router.Path("/").HandlerFunc(s.Index)
		router.Path("/css").HandlerFunc(s.CSS)
	} else {
		log.Infof("Not showing index or listings")
		router.Path("/").HandlerFunc(s.OK)
	}
}

func (s *Lister) start() {
	go func() {
		log.Infof("Refreshing repositories")
		s.repositories = s.getRepositories()
		s.lastPoll = time.Now()
		log.Infof("Repository list refreshed")
		for range time.Tick(*RefreshInterval) {
			log.Infof("Refreshing repositories")
			s.repositories = s.getRepositories()
			s.lastPoll = time.Now()
			log.Infof("Repository list refreshed")
		}
	}()
}

func (s *Lister) JS(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Add("Content-Type", "application/javascript")
	err := s.templates.ExecuteTemplate(writer, "main.js", nil)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
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
	err := s.templates.ExecuteTemplate(writer, "listingIndex.gohtml", ListingIndex{
		Title:        s.getHostname(req),
		Repositories: s.repositories,
		LastPolled:   s.lastPoll,
	})
	if err != nil {
		log.Printf("Unable to output template: %s", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Lister) getRepositories() *RepositoryList {
	publicRepositories, err := s.getCatalog()
	if err != nil {
		log.Printf("Error: %s", err)
		return nil
	}
	repositoryList := &RepositoryList{}
	for index := range publicRepositories {
		repoInfo, err := s.getRepoInfo(publicRepositories[index])
		if err == nil {
			repositoryList.Repositories = append(repositoryList.Repositories, repoInfo)
		} else {
			log.Infof("Unable to update repository list: %s", err.Error())
		}
	}
	return repositoryList
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
	list := &DistributionRepository{}
	err = json.Unmarshal(listBody, list)
	if err != nil {
		return nil, errors.New("unable to unmarshall response")
	}
	list.Name = repository
	taggedRepository, err := s.getTaggedRepository(list)
	if err != nil {
		return nil, err
	}
	return taggedRepository, nil
}

func (s *Lister) getTaggedRepository(repository *DistributionRepository) (*Repository, error) {
	repo := &Repository{
		Name: repository.Name,
	}
	for index := range repository.Tags {
		sha, err := s.getTagSHA(repository, repository.Tags[index])
		if err != nil {
			log.Printf("Unable to get digest for tag: %s", err.Error())
			repo.Tags = append(repo.Tags, Tag{
				Name: repository.Tags[index],
				SHA:  "error",
			})
			continue
		}
		repo.Tags = append(repo.Tags, Tag{
			Name: repository.Tags[index],
			SHA:  sha,
		})
	}
	return repo, nil
}

func (s *Lister) getTagSHA(repository *DistributionRepository, tag string) (string, error) {
	accessToken, err := s.TokenProvider(repository.Name)
	if err != nil {
		return "", errors.New("error obtaining access token")
	}
	httpClient := http.Client{}
	getRequest, err := http.NewRequest(http.MethodHead, fmt.Sprintf("%s/v2/%s/manifests/%s", *RegistryHost, repository.Name, tag), nil)
	if err != nil {
		return "", errors.New("error creating request")
	}
	getRequest.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	getRequest.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json")
	getRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := httpClient.Do(getRequest)
	if err != nil {
		return "", errors.New("unable to perform request")
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("bad response code: %d", resp.StatusCode)
	}
	sha := resp.Header.Get("Docker-Content-Digest")
	if len(sha) == 0 {
		return "", fmt.Errorf("no content digest specified")
	}
	return sha, nil
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
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad response code: %d", resp.StatusCode)
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
