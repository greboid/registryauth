package auth

import (
	"flag"
	"fmt"

	log "github.com/sirupsen/logrus"
)

var (
	Debug = flag.Bool("debug", false, "Show debug logging")
)

type Formatter struct {
	Debug bool
}

func InitFormatter() {
	if *Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.SetFormatter(Formatter{Debug: *Debug})
}

func (f Formatter) Format(entry *log.Entry) ([]byte, error) {
	if f.Debug {
		return []byte(fmt.Sprintf("%s %s: %s [%s]\n", entry.Time.Format("2006/01/02 15:04:05"), entry.Level, entry.Message, entry.Data)), nil
	}
	return []byte(fmt.Sprintf("%s %s: %s\n", entry.Time.Format("2006/01/02 15:04:05"), entry.Level, entry.Message)), nil
}
