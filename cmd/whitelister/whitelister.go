package main

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	router "github.com/go-chi/chi"
	"github.com/spf13/viper"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"whitelister/server/handlers"
	"whitelister/server/middleware"
	"whitelister/server/routes"
)

const keyENV = "APP_ENV"

var AppVersion = "dev"
var AppVersionJSON = ""
var AppName = "whitelister"

func readConfig(env string) {
	if len(env) > 0 {
		env = fmt.Sprintf(".%s", env)
	}

	viper.SetConfigFile(fmt.Sprintf("./config/app%s.yml", env))
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}
}

// For govvv versioning of executable
var GitCommit, GitBranch, GitState, GitSummary, BuildDate, Version string

var logger *log.Logger

func init() {
	env := os.Getenv(keyENV)

	logger = log.New()
	logger.Info(fmt.Sprintf("Starting %s on %s env..", AppName, env))

	readConfig(env)

	v := flag.Bool("v", false, "Prints the version details")
	version := flag.Bool("version", false, "Prints all the version details")
	versionJSON := flag.Bool("json", false, "Prints all the version details in JSON format")
	flag.Parse()

	if *v {
		fmt.Printf("Version: %s\n", Version)
		os.Exit(0)
	}

	AppVersionJSON = fmt.Sprintf("{\"version\":\"%s\",\"build_date\":\"%s\",\"git_commit\":\"%s\",\"git_branch\":\"%s\",\"git_state\":\"%s\",\"git_summary\":\"%s\"}\n", Version, BuildDate, GitCommit, GitBranch, GitState, GitSummary)
	AppVersion = fmt.Sprintf("Version: %s, %s\nBuilt from: %s (%s), %s, %s\n", Version, BuildDate, GitCommit, GitBranch, GitState, GitSummary)

	switch *version {
	case true:
		switch *versionJSON {
		case true:
			fmt.Println(AppVersionJSON)
		default:
			fmt.Println(AppVersion)
		}
		os.Exit(0)
	}
}


func main() {
	host, port := viper.GetString("host"), viper.GetString("port")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT)

	r := routes.GetRoutesList(logger, router.NewRouter(), middleware.NewLog(logger, true))

	// Health and info endpoints
	r.Add("/ping", "GET", handlers.NewPing(logger, AppVersionJSON).Handler)

	// Web UI endpoints
	ui := handlers.NewUI(logger)
	r.Add("/", "GET", ui.Index)

	// API endpoints for Cloudflare whitelisting and IP management
	cloudflare := handlers.NewCloudflare(logger)
	r.Add("/api/whitelist/cloudflare", "POST", cloudflare.WhitelistCloudflare)
	r.Add("/api/cloudflare/ips", "GET", cloudflare.ListCloudflareIPs)
	r.Add("/api/health", "GET", cloudflare.HealthCheck)
	r.Add("/api/public-ip", "GET", cloudflare.GetPublicIP)

	// API endpoints for secure key management
	keyManager := handlers.NewKeyManager(logger)
	r.Add("/api/keys/services", "GET", keyManager.ListAllServices)
	r.Add("/api/keys/service", "GET", keyManager.ListServiceKeys)

	// API endpoints for Hostinger VPS management
	hostinger := handlers.NewHostinger(logger)
	r.Add("/api/hostinger/firewalls", "POST", hostinger.ListFirewalls)
	r.Add("/api/hostinger/firewall/create", "POST", hostinger.CreateFirewall)
	r.Add("/api/hostinger/firewall/rules", "POST", hostinger.ListFirewallRules)
	r.Add("/api/hostinger/firewall/enable", "POST", hostinger.EnableFirewall)
	r.Add("/api/hostinger/firewall/disable", "POST", hostinger.DisableFirewall)
	r.Add("/api/hostinger/test", "POST", hostinger.TestConnection)

	r.Parse()

	//ping := handlers.NewPing(logger, appVersionJSON)
    //r.Get("/ping", ping.Handler)

    //hello := handlers.NewHello(logger)
	//r.Get("/", hello.Handler)

    //whitelistScaleway := handlers.NewWhitelistScaleway(logger)
    //r.Post("/whitelist/scaleway", whitelistScaleway.WhitelistScaleway)

    //lister := handlers.NewLister(logger)
    //r.Post("/list/securityGroups", lister.ScalewaySG)

	httpErr := make(chan error, 1)
	go func() {
		logger.Info(fmt.Sprintf("Started server on %s:%s..", host, port))
		httpErr <- http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), r.Router)
	}()

	select {
    case err := <-httpErr:
        logger.Error(err.Error())
    case <-stop:
        logger.Info("Stopped via signal")
    }

    logger.Info(fmt.Sprintf("Stopping %s..", AppName))
}
