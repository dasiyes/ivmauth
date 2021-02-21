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
	"github.com/go-kit/kit/log"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"

	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/firestoredb"
	"ivmanto.dev/ivmauth/inmem"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
	"ivmanto.dev/ivmauth/server"
)

const (
	defaultPort = "8080"
	defaultGCP  = "ivmauth"
)

func main() {
	var (
		port      = envString("PORT", defaultPort)
		cid       = envString("clientID", "")
		csc       = envString("clientSecret", "")
		projectID = envString("GCP_PROJECT", defaultGCP)

		httpAddr = flag.String("http.addr", ":"+port, "HTTP listen [localhost]:port")
		inmemory = flag.Bool("inmem", false, "use in-memory repositories")
	)

	flag.Parse()

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
		logger = log.With(logger, "ts", log.DefaultTimestamp)
	}

	// SETUP repositories
	var (
		authrequests ivmanto.RequestRepository
		pubkeys      ivmanto.PublicKeySetRepository
		oidprv       ivmanto.OIDProviderRepository
		clients      ivmanto.ClientRepository
	)

	// The Public Key Set is always in mem cache
	pubkeys = inmem.NewPKSRepository()
	oidprv = inmem.NewOIDProviderRepository()

	if *inmemory {

		authrequests = inmem.NewRequestRepository()
		clients = inmem.NewClientRepository()

	} else {

		ctx := context.TODO()
		client, err := firestore.NewClient(ctx, projectID)
		if err != nil {
			panic(err)
		}

		defer client.Close()

		authrequests, _ = firestoredb.NewRequestRepository(&ctx, "authrequests", client)
		clients, _ = firestoredb.NewClientRepository(&ctx, "clients", client)
		// TODO: [IVMCA-12] add the rest of the repos
	}

	// Facilitate testing by adding some sample data
	storeTestData(clients, cid, csc)

	fieldKeys := []string{"method"}

	// Configure some questionable dependencies.

	// initiating services
	var au authenticating.Service
	{
		au = authenticating.NewService(authrequests, clients)
		au = authenticating.NewLoggingService(log.With(logger, "component", "authenticating"), au)
		au = authenticating.NewInstrumentingService(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "api",
				Subsystem: "authenticating_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "api",
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
				Namespace: "api",
				Subsystem: "pksrefreshing_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "api",
				Subsystem: "pksrefreshing_service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
			pkr,
		)
	}

	// creating a new http server to handle the requests
	srv := server.New(au, pkr, log.With(logger, "component", "http"))

	errs := make(chan error, 2)
	go func() {
		_ = logger.Log("transport", "http", "address", *httpAddr, "msg", "listening")
		errs <- http.ListenAndServe(*httpAddr, srv)
	}()
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	_ = logger.Log("terminated", <-errs)
}

func envString(env, fallback string) string {
	e := os.Getenv(env)
	if e == "" {
		return fallback
	}
	return e
}

func storeTestData(c ivmanto.ClientRepository, cid, csc string) {
	client1 := ivmanto.NewClient(ivmanto.ClientID(cid), ivmanto.Active)
	client1.ClientSecret = csc
	if err := c.Store(client1); err != nil {
		fmt.Printf("error saving test dataset 1: %#v;\n", err)
	}

	client2 := ivmanto.NewClient("xxx.apps.ivmanto.dev", ivmanto.Active)
	client2.ClientSecret = "ivmanto-2021"
	if err := c.Store(client2); err != nil {
		fmt.Printf("error saving test dataset 2: %#v;\n", err)
	}
}
