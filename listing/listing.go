package listing

import (
	"embed"
	"flag"
	"html/template"
	"time"

	"github.com/distribution/distribution/v3/registry/auth/token"
	"github.com/gorilla/mux"
	"github.com/greboid/registryauth/auth"
	log "github.com/sirupsen/logrus"
)

var (
	ShowIndex       = flag.Bool("show-index", false, "Show an index page, rather than just a 200 response")
	ShowListings    = flag.Bool("show-listings", true, "Index page lists public repositories")
	PullHostname    = flag.String("pull-hostname", "", "Hostname to show on listings and info page, will default to the request hostname")
	RegistryHost    = flag.String("registry-host", "http://localhost:8080", "The URL of the registry being listed")
	RefreshInterval = flag.Duration("refresh-interval", 60*time.Second, "The time between registry refreshes")
)

//go:embed templates
var templates embed.FS

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

type Repository struct {
	Name string
	Tags []Tag
}

type Tag struct {
	Name string
	SHA  string
	Size int
}

type ListingIndex struct {
	Title        string
	Repositories *RepositoryList
	LastPolled   time.Time
}

type Index struct {
	Title string
}

func NewLister(publicPrefixes []string, getFullToken func(repository ...string) (string, error)) *Lister {
	lister := &Lister{
		TokenProvider:  getFullToken,
		PublicPrefixes: publicPrefixes,
	}
	return lister
}

func (s *Lister) Initialise(router *mux.Router) {
	s.addRoutes(router)
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

func (s *Lister) getRepositories() *RepositoryList {
	publicRepositories, err := s.getPublicRepositories()
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
	distRepo, err := getTagList(repository, s.TokenProvider)
	if err != nil {
		return nil, err
	}
	taggedRepository, err := s.getTaggedRepository(distRepo)
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
		manifest, err := getRepositoryManifest(repository.Name, repository.Tags[index], s.TokenProvider)
		if err != nil {
			log.Printf("Unable to get manifest for tag: %s", err.Error())
			repo.Tags = append(repo.Tags, Tag{
				Name: repository.Tags[index],
				SHA:  "error",
				Size: manifest.Size,
			})
			continue
		}
		repo.Tags = append(repo.Tags, Tag{
			Name: repository.Tags[index],
			SHA:  manifest.SHA,
			Size: manifest.Size,
		})
	}
	return repo, nil
}

func (s *Lister) getPublicRepositories() ([]string, error) {
	catalog, err := getCatalog(s.TokenProvider)
	if err != nil {
		return nil, err
	}
	var publicRepositories []string
	for index := range catalog.Repositories {
		if auth.IsScopePublic(s.PublicPrefixes, &token.ResourceActions{
			Type:    "repository",
			Name:    catalog.Repositories[index],
			Actions: []string{"pull"},
		}) {
			publicRepositories = append(publicRepositories, catalog.Repositories[index])
		}
	}
	return publicRepositories, nil
}
