package authenticating

import (
	"net/http"
	"time"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
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

func (s *instrumentingService) RegisterNewRequest(rh *http.Header, body *core.AuthRequestBody, client *core.Client) (core.AuthRequestID, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "RegisterNewRequest").Add(1)
		s.requestLatency.With("method", "RegisterNewRequest").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.RegisterNewRequest(rh, body, client)
}

func (s *instrumentingService) Validate(
	rh *http.Header,
	body *core.AuthRequestBody,
	pks pksrefreshing.Service,
	client *core.Client) (*core.AccessToken, error) {

	defer func(begin time.Time) {
		s.requestCount.With("method", "Validate").Add(1)
		s.requestLatency.With("method", "Validate").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.Validate(rh, body, pks, client)
}

func (s *instrumentingService) AuthenticateClient(r *http.Request) (rc *core.Client, err error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "AuthenticateClient").Add(1)
		s.requestLatency.With("method", "AuthenticateClient").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.AuthenticateClient(r)
}

func (s *instrumentingService) GetRequestBody(r *http.Request) (b *core.AuthRequestBody, err error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "GetRequestBody").Add(1)
		s.requestLatency.With("method", "GetRequestBody").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.GetRequestBody(r)
}

func (s *instrumentingService) IssueAccessToken(oidt *core.IDToken, client *core.Client) (*core.AccessToken, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "IssueAccessToken").Add(1)
		s.requestLatency.With("method", "IssueAccessToken").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.IssueAccessToken(oidt, client)
}

func (s *instrumentingService) CheckUserRegistration(oidtoken *core.IDToken) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "CheckUserRegistration").Add(1)
		s.requestLatency.With("method", "CheckUserRegistration").Observe(time.Since(begin).Seconds())
	}(time.Now())
}

func (s *instrumentingService) RegisterUser(names, email, password string) (*core.User, error) {
	defer func(begin time.Time) {
		s.requestCount.With("method", "RegisterUser").Add(1)
		s.requestLatency.With("method", "RegisterUser").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.RegisterUser(names, email, password)
}

func (s *instrumentingService) UpdateUser(u *core.User) error {
	defer func(begin time.Time) {
		s.requestCount.With("method", "RegisterUser").Add(1)
		s.requestLatency.With("method", "RegisterUser").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.next.UpdateUser(u)
}