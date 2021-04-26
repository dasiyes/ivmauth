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
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"

	"ivmanto.dev/ivmauth/authenticating"
	ivmcfg "ivmanto.dev/ivmauth/config"
	"ivmanto.dev/ivmauth/firestoredb"
	"ivmanto.dev/ivmauth/inmem"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
	"ivmanto.dev/ivmauth/server"
)

func main() {

	var (
		mc  = context.Background()
		cfg = ivmcfg.Init()
	)

	type Cfgk string

	var (
		inmemory = flag.Bool("inmem", false, "use in-memory repositories")
		// TODO:
		env = flag.String("env", "dev", "The environment where the service will run. It will define the config file name to load by adding suffix '-$env' to 'config'. Accepted values: dev|staging|prod ")
	)

	flag.Parse()

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
		logger = log.With(logger, "ts", log.DefaultTimestamp)
	}

	// Load service configuration
	if err := cfg.LoadCfg(env, log.With(logger, "component", "config")); err != nil {
		logger.Log("Exit", "Unable to proceed starting the server...")
		os.Exit(1)
	}

	var (
		httpAddr  = cfg.GetHTTPAddr()
		projectID = cfg.GCPPID()
	)

	// SETUP repositories
	var (
		authrequests ivmanto.RequestRepository
		pubkeys      ivmanto.PublicKeySetRepository
		oidprv       ivmanto.OIDProviderRepository
		clients      ivmanto.ClientRepository
		users        ivmanto.UserRepository
	)

	// The Public Key Set is always in mem cache
	pubkeys = inmem.NewPKSRepository()
	oidprv = inmem.NewOIDProviderRepository()

	if *inmemory {

		authrequests = inmem.NewRequestRepository()
		clients = inmem.NewClientRepository()
		users = inmem.NewUserRepository()

	} else {

		ctx := context.WithValue(mc, Cfgk("ivm"), cfg)
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
	sm, err := ivmsesman.NewSesman(ivmsesman.Memory, (*ivmsesman.SesCfg)(cfg.GetSessManCfg()))
	if err != nil {
		_ = level.Error(logger).Log("error-sesman", err.Error())
		os.Exit(1)
	}

	// Running GC in separate go routine
	go sm.GC()

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
	srv := server.New(au, pkr, log.With(logger, "component", "http"), sm)

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

func storeTestData(c ivmanto.ClientRepository, cid, csc string) {
	client1 := ivmanto.NewClient(ivmanto.ClientID(cid), ivmanto.Active)
	client1.ClientSecret = csc
	if err := c.Store(client1); err != nil {
		fmt.Printf("error saving test dataset 1: %#v;\n", err)
	}
}
