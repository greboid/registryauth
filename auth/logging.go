package auth

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

type Formatter struct{}

func (f Formatter) Format(entry *log.Entry) ([]byte, error) {
	return []byte(fmt.Sprintf("%s %s: %s\n", entry.Time.Format("2006/01/02 15:04:05"), entry.Level, entry.Message)), nil
}
