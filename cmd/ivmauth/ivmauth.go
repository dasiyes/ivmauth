package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/kit/log"
	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/server"
)

const (
	defaultPort = "8080"
)

func main() {
	var (
		port = envString("PORT", defaultPort)

		httpAddr = flag.String("http.addr", ":"+port, "HTTP listen [localhost]:port")
	)

	flag.Parse()

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
		logger = log.With(logger, "ts", log.DefaultTimestamp)
	}

	// setup repositories // TODO: [uncomment and set once hte DB is place or inmemory implemented ]
	// var (
	// 	locations ivmanto.LocationRepository
	// 	requests  ivmanto.RequestorRepository
	// )

	// Facilitate testing by adding some sample data
	storeTestData("tb added")

	// Configure some questionable dependencies.

	// initiating a service
	var au authenticating.Service
	// TODO: initiate the service as per sample below
	// bs = booking.NewService(cargos, locations, handlingEvents, rs)
	// bs = booking.NewLoggingService(log.With(logger, "component", "booking"), bs)
	// bs = booking.NewInstrumentingService(
	// 	kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
	// 		Namespace: "api",
	// 		Subsystem: "booking_service",
	// 		Name:      "request_count",
	// 		Help:      "Number of requests received.",
	// 	}, fieldKeys),
	// 	kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
	// 		Namespace: "api",
	// 		Subsystem: "booking_service",
	// 		Name:      "request_latency_microseconds",
	// 		Help:      "Total duration of requests in microseconds.",
	// 	}, fieldKeys),
	// 	bs,
	// )

	// creating a new http server to handle the requests
	srv := server.New(au, log.With(logger, "component", "http"))

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
