package listing

import (
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func (s *Lister) addRoutes(router *mux.Router) {
	if *ShowListings {
		log.Infof("Enabling listings")
		s.getTemplates()
		router.Path("/").HandlerFunc(s.ListingIndex)
		router.Path("/css").HandlerFunc(s.CSS)
		router.Path("/js").HandlerFunc(s.JS)
		s.start()
	} else if *ShowIndex {
		log.Infof("Showing index only")
		s.getTemplates()
		router.Path("/").HandlerFunc(s.Index)
		router.Path("/css").HandlerFunc(s.CSS)
	} else {
		log.Infof("Not showing index or listings")
		router.Path("/").HandlerFunc(s.OK)
	}
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

func (s *Lister) getTemplates() {
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
}

func (s *Lister) getHostname(req *http.Request) string {
	if *PullHostname != "" {
		return *PullHostname
	} else if req != nil && req.Host != "" {
		return req.Host
	}
	return "Docker Registry"
}
