package pksrefreshing

import (
	"crypto/rsa"
	"time"

	"github.com/go-kit/kit/log"
)

type loggingService struct {
	logger log.Logger
	next   Service
}

// NewLoggingService returns a new instance of a logging Service.
func NewLoggingService(logger log.Logger, s Service) Service {
	return &loggingService{logger, s}
}

func (s *loggingService) NewPKS(identityProvider string, pkURL string) (err error) {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "pksrefreshing",
			"identityProvider", identityProvider,
			"pkURL", pkURL,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.NewPKS(identityProvider, pkURL)
}

func (s *loggingService) GetRSAPublicKey(identityProvider string) (pk rsa.PublicKey, err error) {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "GetRSAPublicKey",
			"identityProvider", identityProvider,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.GetRSAPublicKey(identityProvider)
}
