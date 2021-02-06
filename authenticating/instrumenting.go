package authenticating

import (
	"net/http"
	"time"

	"github.com/go-kit/kit/metrics"
	"ivmanto.dev/ivmauth/ivmanto"
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

func (s *instrumentingService) RegisterNewRequest(rh http.Header, body ivmanto.AuthRequestBody) (ivmanto.SessionID, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "authenticate").Add(1)
		s.requestLatency.With("method", "authenticate").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.RegisterNewRequest(rh, body)
}

func (s *instrumentingService) Validate(id ivmanto.SessionID) (ivmanto.AccessToken, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "validate").Add(1)
		s.requestLatency.With("method", "validate").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.Validate(id)
}
