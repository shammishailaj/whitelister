package routes

import (
	"github.com/go-chi/chi"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

type Route struct {
	Pattern string
	Method string
	Handler http.HandlerFunc
}

func (r *Route) New(pattern, method string, h http.HandlerFunc) *Route {
	r.Pattern = pattern
	r.Method = method
	r.Handler = h
	return r
}

type Routes struct {
	Routes []*Route
	Router *chi.Mux
	Log *log.Logger
}

func (r *Routes) Init(logger *log.Logger, router *chi.Mux) *Routes {
	r.Log = logger
	r.Router = router
	return r
}

func (r *Routes) Add(pattern, method string, h http.HandlerFunc) {
	t := new(Route).New(pattern, strings.ToUpper(method), h)
	r.Routes = append(r.Routes, t)
}

func (r *Routes) Parse() {
	if r.Routes == nil {
		r.Log.Errorf("Routes is nil. Not parsing routes")
		return
	}
	for routeNumber, route := range r.Routes {
		r.Log.Infof("Setting-up Route #%d %s %s", routeNumber, route.Method, route.Pattern)
		r.Router.Method(route.Method, route.Pattern, route.Handler)
	}
}