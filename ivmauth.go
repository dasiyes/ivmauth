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

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
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

	fmt.Printf("Start loading ...\n")
	// Set the run-time arguments as flags
	var (
		inmemory = flag.Bool("inmem", false, "use in-memory repositories")
		env      = flag.String("env", "dev", "The environment where the service will run. It will define the config file name to load by adding suffix '-$env' to 'config'. Accepted values: dev|staging|prod ")
		cf       = flag.String("c", "config.yaml", "The configuration file name to use for oauth server config values and dependent services")
	)

	fmt.Printf("  ... parse run-time flags\n")
	flag.Parse()

	fmt.Printf("  ... seting up logger\n")
	// Initiating the services logger
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
		logger = level.NewFilter(logger, level.AllowDebug())
		logger = log.With(logger, "ts", log.DefaultTimestamp)
	}

	fmt.Printf("  ... loading configuration\n")
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

	fmt.Printf("  ... setting up repositories\n")
	// SETUP repositories
	var (
		authrequests core.RequestRepository
		pubkeys      core.PublicKeySetRepository
		oidprv       core.OIDProviderRepository
		clients      core.ClientRepository
		users        core.UserRepository
		keyJournal   core.KJR
	)

	type Cfgk string

	if *inmemory {

		authrequests = inmem.NewRequestRepository()
		pubkeys = inmem.NewPKSRepository()
		oidprv = inmem.NewOIDProviderRepository()
		clients = inmem.NewClientRepository()
		users = inmem.NewUserRepository()

	} else {

		ctx := context.WithValue(ctx, Cfgk("ivm"), cfg)
		client, err := firestore.NewClient(ctx, projectID)
		if err != nil {
			_ = level.Error(logger).Log("firestore client init error", err.Error(), "Exit", "Unable to proceed starting the server...")
			os.Exit(1)
		}

		defer client.Close()

		// Collection naming convention:
		//  * Must be valid UTF-8 characters
		//  * Must be no longer than 1,500 bytes
		//  * Cannot contain a forward slash (/)
		//  * Cannot solely consist of a single period (.) or double periods (..)
		//  * Cannot match the regular expression __.*__

		authrequests, _ = firestoredb.NewRequestRepository(&ctx, "authrequests", client)
		pubkeys = firestoredb.NewPKSRepository(&ctx, "pubkeys", client)
		oidprv = firestoredb.NewOIDProviderRepository(&ctx, "openID-providers", client)
		clients, _ = firestoredb.NewClientRepository(&ctx, "clients", client)
		users, _ = firestoredb.NewUserRepository(&ctx, "users", client)
		keyJournal = firestoredb.NewKeysJournalRepo(&ctx, "keys-journal", client)
	}

	fieldKeys := []string{"method"}

	// Configure some questionable dependencies.

	fmt.Printf("  ... setting up Session Manager\n")
	// Create a Session Manager
	sm, err := ivmsesman.NewSesman(ivmsesman.Firestore, (*ivmsesman.SesCfg)(cfg.GetSessManCfg()))
	if err != nil {
		_ = level.Error(logger).Log("error-sesman", err.Error())
		os.Exit(1)
	}

	fmt.Printf("  ... instantiate the tempalatesCache\n")
	// Instantiate the tempalatesCache for the SSO ui pages
	tc, err := ssoapp.NewTemplateCache("./ui/html/")
	if err != nil {
		_ = level.Error(logger).Log("error-template-cache", err.Error())
		os.Exit(1)
	}
	ssolgr := log.With(logger, "component", "ivmSSO")
	ivmSSO := ssoapp.NewIvmSSO(tc, &ssolgr, users)

	fmt.Printf("  ... initiating services\n")
	// initiating services

	var pkr pksrefreshing.Service
	{
		pkr = pksrefreshing.NewService(pubkeys, keyJournal, oidprv, cfg.GetIvmantoOIDC())
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

	var au authenticating.Service
	{
		au = authenticating.NewService(pkr, authrequests, keyJournal, clients, users, cfg)
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

	fmt.Printf("  ... initiating OpenID Connect Providers\n")
	// Initiating OpenID Connect Providers
	errors := pkr.InitOIDProviders(cfg.GetOIDPS())
	if len(errors) > 0 {
		for i, err := range errors {
			fmt.Printf("error %d, when initiating OpenID Providers. error [%#v]\n", i+1, err)
		}
	}

	fmt.Printf("  ... finalize config\n\n")
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
