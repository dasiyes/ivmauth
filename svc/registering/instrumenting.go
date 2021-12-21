package registering

import (
	"time"

	"github.com/dasiyes/ivmauth/core"
	"github.com/go-kit/kit/metrics"
)

type instrumentingService struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	next           Service
}

// NewInstrumentingService returns an instance of an instrumenting Service.
func NewInstrumentingService(counter metrics.Counter, latency metrics.Histogram, s Service) Service {
	return &instrumentingService{
		requestCount:   counter,
		requestLatency: latency,
		next:           s,
	}
}

func (s *instrumentingService) RegisterUser(names, email, password, provider, state string, subCode core.SubCode) (err error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "RegisterUser").Add(1)
		s.requestLatency.With("method", "RegisterUser").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.RegisterUser(names, email, password, provider, state, subCode)
}

func (s *instrumentingService) ActivateUser(userId, subcode, state string) (err error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "ActivateUser").Add(1)
		s.requestLatency.With("method", "ActivateUser").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.ActivateUser(userId, subcode, state)
}
