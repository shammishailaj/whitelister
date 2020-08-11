package utils

import (
	log "github.com/sirupsen/logrus"
)

type Utils struct {
	debug bool
	l *log.Logger
}

func New(l *log.Logger) *Utils{
	return &Utils{
		debug: false,
		l: l,
	}
}
