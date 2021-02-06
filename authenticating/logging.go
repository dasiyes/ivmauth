package authenticating

import (
	"net/http"
	"time"

	"github.com/go-kit/kit/log"

	"ivmanto.dev/ivmauth/ivmanto"
)

type loggingService struct {
	logger log.Logger
	next   Service
}

// NewLoggingService returns a new instance of a logging Service.
func NewLoggingService(logger log.Logger, s Service) Service {
	return &loggingService{logger, s}
}

func (s *loggingService) Validate(id ivmanto.SessionID) (at ivmanto.AccessToken, err error) {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "validate",
			"session_id", id,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.Validate(id)
}

func (s *loggingService) RegisterNewRequest(rh http.Header, body ivmanto.AuthRequestBody) (id ivmanto.SessionID, err error) {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "RegisterNewRequest",
			"session_id", id,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.RegisterNewRequest(rh, body)
}
