package handlers

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

type Ping struct {
	l *log.Logger
	semVer string
}

func NewPing(l *log.Logger, version string) *Ping{
	return &Ping{
		l: l,
		semVer: version,
	}
}

func (p *Ping) Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	//err := json.NewEncoder(w).Encode(map[string]string{
	//	"version": p.semVer,
	//})
	//if err != nil {
	//    p.l.Warn(err.Error())
	//
	//	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	//	return
	//}
	w.Write([]byte(p.semVer))
}