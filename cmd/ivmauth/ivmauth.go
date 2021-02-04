package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/kit/log"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"

	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/inmem"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
	"ivmanto.dev/ivmauth/server"
)

const (
	defaultPort = "8080"
)

func main() {
	var (
		port = envString("PORT", defaultPort)

		httpAddr = flag.String("http.addr", ":"+port, "HTTP listen [localhost]:port")
		inmemory = flag.Bool("inmem", false, "use in-memory repositories")
	)

	flag.Parse()

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
		logger = log.With(logger, "ts", log.DefaultTimestamp)
	}

	// setup repositories // TODO: [uncomment and set once hte DB is place or inmemory implemented ]
	var (
		authrequests ivmanto.RequestRepository
		pubkeys      ivmanto.PublicKeySetRepository
	)

	// The Public Key Set is always in mem cache
	pubkeys = inmem.NewPKSRepository()

	if *inmemory {
		authrequests = inmem.NewRequestRepository()
	} else {
		// TODO: implement db repositories
	}

	// Facilitate testing by adding some sample data
	storeTestData("tb added")

	fieldKeys := []string{"method"}

	// Configure some questionable dependencies.

	// initiating services
	var au authenticating.Service
	{
		au = authenticating.NewService(authrequests)
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
		pkr = pksrefreshing.NewService(pubkeys)
		pkr = pksrefreshing.NewLoggingService(log.With(logger, "component", "booking"), pkr)
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
		logger.Log("transport", "http", "address", *httpAddr, "msg", "listening")
		errs <- http.ListenAndServe(*httpAddr, srv)
	}()
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	logger.Log("terminated", <-errs)
}

func envString(env, fallback string) string {
	e := os.Getenv(env)
	if e == "" {
		return fallback
	}
	return e
}

func storeTestData(t string) {
	// TODO: implement saving test data
}
