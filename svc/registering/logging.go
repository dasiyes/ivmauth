package registering

import (
	"fmt"
	"time"

	"github.com/dasiyes/ivmauth/core"
	"github.com/go-kit/log"
)

type loggingService struct {
	logger log.Logger
	next   Service
}

// NewLoggingService returns a new instance of a logging Service.
func NewLoggingService(logger log.Logger, s Service) Service {
	return &loggingService{logger, s}
}

func (s *loggingService) RegisterUser(names, email, password, provider string, subCode core.SubCode) (err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "RegisterUser",
			"took", time.Since(begin),
			"error", fmt.Sprintf("%v", err),
			"registering_user_id", email,
		)
	}(time.Now())
	return s.next.RegisterUser(names, email, password, provider, subCode)
}

func (s *loggingService) ActivateUser(userId, subcode string) (err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "RegisterUser",
			"took", time.Since(begin),
			"error", fmt.Sprintf("%v", err),
			"activate_user_subCode", subcode,
		)
	}(time.Now())
	return s.next.ActivateUser(userId, subcode)
}
