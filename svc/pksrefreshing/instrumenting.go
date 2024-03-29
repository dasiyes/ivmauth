package pksrefreshing

import (
	"math/big"
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

func (s *instrumentingService) InitOIDProviders(oidps []string) (errs []error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "InitOIDProviders").Add(1)
		s.requestLatency.With("method", "InitOIDProviders").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.InitOIDProviders(oidps)
}

func (s *instrumentingService) GetRSAPublicKey(identityProvider string, kid string) (n *big.Int, e int, err error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "GetRSAPublicKey").Add(1)
		s.requestLatency.With("method", "GetRSAPublicKey").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.GetRSAPublicKey(identityProvider, kid)
}

func (s *instrumentingService) GetPKSCache(identityProvider string) (*core.PublicKeySet, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "GetPKSCache").Add(1)
		s.requestLatency.With("method", "GetPKSCache").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.GetPKSCache(identityProvider)
}

// func (s *instrumentingService) DownloadPKSinCache(identityProvider string) (err error) {
// 	defer func(begin time.Time) {
// 		s.requestCount.With("method", "DownloadPKSinCache").Add(1)
// 		s.requestLatency.With("method", "DownloadPKSinCache").Observe(time.Since(begin).Seconds())
// 		if err != nil {
// 			s.requestCount.With("method", "DownloadPKSinCache-with-error").Add(1)
// 		}
// 	}(time.Now())

// 	return s.next.DownloadPKSinCache(identityProvider)
// }

func (s *instrumentingService) GetIssuerVal(provider string) (string, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "GetIssuerVal").Add(1)
		s.requestLatency.With("method", "GetIssuerVal").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.GetIssuerVal(provider)
}

func (s *instrumentingService) PKSRotator(pks *core.PublicKeySet) error {
	defer func(begin time.Time) {
		s.requestCount.With("method", "PKSRotator").Add(1)
		s.requestLatency.With("method", "PKSRotator").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.PKSRotator(pks)
}

func (s *instrumentingService) OIDPExists(provider string) (bool, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "OIDPExists").Add(1)
		s.requestLatency.With("method", "OIDPExists").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.OIDPExists(provider)
}

func (s *instrumentingService) GetOIDProvider(provider string) (*core.OIDProvider, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "GetOIDProvider").Add(1)
		s.requestLatency.With("method", "GetOIDProvider").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.GetOIDProvider(provider)
}
