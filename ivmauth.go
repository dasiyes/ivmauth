package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"cloud.google.com/go/firestore"
	"github.com/dasiyes/ivmsesman"
	_ "github.com/dasiyes/ivmsesman/providers/firestore"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/pkg/ssoapp"
	"github.com/dasiyes/ivmauth/svc/authenticating"
	ivmcfg "github.com/dasiyes/ivmconfig/src/pkg/config"

	"github.com/dasiyes/ivmauth/dataservice/firestoredb"
	"github.com/dasiyes/ivmauth/dataservice/inmem"
	"github.com/dasiyes/ivmauth/server"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
)

func main() {

	// Set the run-time arguments as flags
	var (
		inmemory = flag.Bool("inmem", false, "use in-memory repositories")
		// TODO:
		env = flag.String("env", "dev", "The environment where the service will run. It will define the config file name to load by adding suffix '-$env' to 'config'. Accepted values: dev|staging|prod ")
		cf  = flag.String("c", "config.yaml", "The configuration file name to use for oauth server config values and dependent services")
	)

	flag.Parse()

	// Initiating the services logger
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
		logger = level.NewFilter(logger, level.AllowDebug())
		logger = log.With(logger, "ts", log.DefaultTimestamp)
	}

	// Initiate top level context and config vars
	var (
		ctx = context.Background()
		cfg = ivmcfg.Init(env, log.With(logger, "component", "config"))
	)

	// Load the service configuration from a file
	if err := cfg.LoadConfig(*cf, log.With(logger, "component", "config")); err != nil {
		_ = level.Error(logger).Log("LoadConfig", "Unable to load service configuration", "Error", err.Error())
		os.Exit(1)
	}

	var (
		httpAddr  string = fmt.Sprintf("%s:%d", "", cfg.GetAuthSvcCfg().Port)
		projectID        = cfg.GCPPID()
	)

	// SETUP repositories
	var (
		authrequests core.RequestRepository
		pubkeys      core.PublicKeySetRepository
		oidprv       core.OIDProviderRepository
		clients      core.ClientRepository
		users        core.UserRepository
	)

	// The Public Key Set is always in mem cache
	pubkeys = inmem.NewPKSRepository()
	oidprv = inmem.NewOIDProviderRepository()

	type Cfgk string

	if *inmemory {

		authrequests = inmem.NewRequestRepository()
		clients = inmem.NewClientRepository()
		users = inmem.NewUserRepository()

	} else {

		ctx := context.WithValue(ctx, Cfgk("ivm"), cfg)
		client, err := firestore.NewClient(ctx, projectID)
		if err != nil {
			logger.Log("firestore client init error", err.Error(), "Exit", "Unable to proceed starting the server...")
			os.Exit(1)
		}

		defer client.Close()

		authrequests, _ = firestoredb.NewRequestRepository(&ctx, "authrequests", client)
		clients, _ = firestoredb.NewClientRepository(&ctx, "clients", client)
		users, _ = firestoredb.NewUserRepository(&ctx, "users", client)
		// TODO: add the rest of the repos

	}

	// Facilitate testing by adding some sample data
	//TODO: initiate cis snd csc
	if *env == "dev" {
		storeTestData(clients, "", "")
	}

	fieldKeys := []string{"method"}

	// Configure some questionable dependencies.

	// Create a Session Manager
	sm, err := ivmsesman.NewSesman(ivmsesman.Firestore, (*ivmsesman.SesCfg)(cfg.GetSessManCfg()))
	if err != nil {
		_ = level.Error(logger).Log("error-sesman", err.Error())
		os.Exit(1)
	}

	// Instantiate the tempalatesCache for the SSO ui pages
	tc, err := ssoapp.NewTemplateCache("./ui/html/")
	if err != nil {
		_ = level.Error(logger).Log("error-template-cache", err.Error())
		os.Exit(1)
	}
	ssolgr := log.With(logger, "component", "ivmSSO")
	ivmSSO := ssoapp.NewIvmSSO(tc, &ssolgr, users)

	// initiating services
	var au authenticating.Service
	{
		au = authenticating.NewService(authrequests, clients, users, cfg)
		au = authenticating.NewLoggingService(log.With(logger, "component", "authenticating"), au)
		au = authenticating.NewInstrumentingService(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "ivmauth",
				Subsystem: "authenticating_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "ivmauth",
				Subsystem: "authenticating_service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
			au,
		)
	}

	var pkr pksrefreshing.Service
	{
		pkr = pksrefreshing.NewService(pubkeys, oidprv)
		pkr = pksrefreshing.NewLoggingService(log.With(logger, "component", "pksrefreshing"), pkr)
		pkr = pksrefreshing.NewInstrumentingService(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "ivmauth",
				Subsystem: "pksrefreshing_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "ivmauth",
				Subsystem: "pksrefreshing_service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
			pkr,
		)
	}

	// creating a new http server to handle the requests
	srv := server.New(au, pkr, log.With(logger, "component", "http"), sm, cfg, ivmSSO)

	errs := make(chan error, 2)
	go func() {
		_ = logger.Log("transport", "http", "address", httpAddr, "msg", "listening")
		errs <- http.ListenAndServe(httpAddr, srv)
	}()
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	_ = logger.Log("terminated", <-errs)
}

func storeTestData(c core.ClientRepository, cid, csc string) {
	client1 := core.NewClient(core.ClientID(cid), core.Active)
	client1.ClientSecret = csc
	if err := c.Store(client1); err != nil {
		fmt.Printf("error saving test dataset 1: %#v;\n", err)
	}
}
