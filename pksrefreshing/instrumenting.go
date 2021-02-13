package pksrefreshing

import (
	"math/big"
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

func (s *instrumentingService) InitOIDProviders() {
	defer func(begin time.Time) {
		s.requestCount.With("method", "InitOIDProviders").Add(1)
		s.requestLatency.With("method", "InitOIDProviders").Observe(time.Since(begin).Seconds())
	}(time.Now())
}

func (s *instrumentingService) GetRSAPublicKey(identityProvider string, kid string) (n *big.Int, e int, err error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "GetRSAPublicKey").Add(1)
		s.requestLatency.With("method", "GetRSAPublicKey").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.GetRSAPublicKey(identityProvider, kid)
}

func (s *instrumentingService) GetPKSCache(identityProvider string) (*ivmanto.PublicKeySet, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "GetPKSCache").Add(1)
		s.requestLatency.With("method", "GetPKSCache").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.GetPKSCache(identityProvider)
}

func (s *instrumentingService) DownloadPKSinCache(identityProvider string) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "DownloadPKSinCache").Add(1)
		s.requestLatency.With("method", "DownloadPKSinCache").Observe(time.Since(begin).Seconds())
	}(time.Now())
}
