package listing

import (
	"fmt"
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
			"TagPrint":  tagPrint,
			"HumanSize": humanBytes,
			"DisplayTime": func(format time.Time) string {
				return format.Format("02-01 15:04")
			},
		}).
		ParseFS(templates, "templates/*.gohtml", "templates/*.css", "templates/*.js"))
}

func tagPrint(input []Tag) string {
	if len(input) == 0 {
		return "No Tags"
	}
	output := ""
	for index := range input {
		if index > 4 {
			output += ", ..."
			break
		}
		if index != 0 {
			output += ", "
		}
		output += input[index].Name + " (" + humanBytes(input[index].Size) + ")"
	}
	return output
}

func humanBytes(b int) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

func (s *Lister) getHostname(req *http.Request) string {
	if *PullHostname != "" {
		return *PullHostname
	} else if req != nil && req.Host != "" {
		return req.Host
	}
	return "Docker Registry"
}
