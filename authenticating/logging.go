package authenticating

import (
	"net/http"
	"time"

	"github.com/go-kit/kit/log"

	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
)

type loggingService struct {
	logger log.Logger
	next   Service
}

// NewLoggingService returns a new instance of a logging Service.
func NewLoggingService(logger log.Logger, s Service) Service {
	return &loggingService{logger, s}
}

func (s *loggingService) Validate(rh http.Header, body *ivmanto.AuthRequestBody, pks pksrefreshing.Service) (at *ivmanto.AccessToken, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "validate",
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.Validate(rh, body, pks)
}

func (s *loggingService) RegisterNewRequest(rh http.Header, body ivmanto.AuthRequestBody) (id ivmanto.SessionID, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "RegisterNewRequest",
			"request_Header_len", len(rh),
			"session_id", id,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.RegisterNewRequest(rh, body)
}

func (s *loggingService) AuthenticateClient(r *http.Request) (rc *ivmanto.Client, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "AuthenticateClient",
			"request_Header_len", len(r.Header),
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.AuthenticateClient(r)
}

func (s *loggingService) GetRequestBody(r *http.Request) (b *ivmanto.AuthRequestBody, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "GetRequestBody",
			"request_Header_len", len(r.Header),
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.GetRequestBody(r)
}

func (s *loggingService) IssueAccessToken(oidt *ivmanto.IDToken) (at *ivmanto.AccessToken, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "IssueAccessToken",
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.IssueAccessToken(oidt)
}
