package authenticating

import (
	"time"

	"github.com/go-kit/kit/log"

	ivmanto "ivmanto.dev/ivmauth"
)

type loggingService struct {
	logger log.Logger
	next   Service
}

// NewLoggingService returns a new instance of a logging Service.
func NewLoggingService(logger log.Logger, s Service) Service {
	return &loggingService{logger, s}
}

func (s *loggingService) Validate(rs ivmanto.RequestSpec) (at ivmanto.AccessToken, err error) {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "validate",
			"origin", rs.Origin,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.Validate(rs)
}

func (s *loggingService) LogNewRequest() (id ivmanto.TrackingID, err error) {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "log",
			"tracking_id", id,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.LogNewRequest()
}
