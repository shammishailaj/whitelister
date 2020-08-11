package routes

import (
	"github.com/go-chi/chi"
	"github.com/sirupsen/logrus"
	"whitelister/server/handlers"
	"whitelister/server/middleware"
)

func GetRoutesList(logger *logrus.Logger, router *chi.Mux, lm *middleware.Log) *Routes {
	router.Use(lm.Handler)
	return &Routes{
		Routes: []*Route{
			{
				Pattern: "/whitelist/scaleway",
				Method:  "POST",
				Handler: handlers.NewWhitelistScaleway(logger).WhitelistScaleway,
			},
			{
				Pattern: "/",
				Method:  "GET",
				Handler: handlers.NewHello(logger).Handler,
			},
			{
				Pattern: "/list/securityGroups",
				Method:  "POST",
				Handler: handlers.NewLister(logger).ScalewaySG,
			},
		},
		Router: router,
		Log:    logger,
	}
}
