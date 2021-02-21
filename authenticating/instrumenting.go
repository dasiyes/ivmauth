package authenticating

import (
	"net/http"
	"time"

	"github.com/go-kit/kit/metrics"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
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

func (s *instrumentingService) RegisterNewRequest(rh *http.Header, body *ivmanto.AuthRequestBody, client *ivmanto.Client) (ivmanto.SessionID, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "RegisterNewRequest").Add(1)
		s.requestLatency.With("method", "RegisterNewRequest").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.RegisterNewRequest(rh, body, client)
}

func (s *instrumentingService) Validate(
	rh *http.Header,
	body *ivmanto.AuthRequestBody,
	pks pksrefreshing.Service,
	client *ivmanto.Client) (*ivmanto.AccessToken, error) {

	defer func(begin time.Time) {
		s.requestCount.With("method", "Validate").Add(1)
		s.requestLatency.With("method", "Validate").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.Validate(rh, body, pks, client)
}

func (s *instrumentingService) AuthenticateClient(r *http.Request) (rc *ivmanto.Client, err error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "AuthenticateClient").Add(1)
		s.requestLatency.With("method", "AuthenticateClient").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.AuthenticateClient(r)
}

func (s *instrumentingService) GetRequestBody(r *http.Request) (b *ivmanto.AuthRequestBody, err error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "GetRequestBody").Add(1)
		s.requestLatency.With("method", "GetRequestBody").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.GetRequestBody(r)
}

func (s *instrumentingService) IssueAccessToken(oidt *ivmanto.IDToken, client *ivmanto.Client) (*ivmanto.AccessToken, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "IssueAccessToken").Add(1)
		s.requestLatency.With("method", "IssueAccessToken").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.IssueAccessToken(oidt, client)
}
