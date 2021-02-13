package pksrefreshing

import (
	"math/big"
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

func (s *loggingService) GetRSAPublicKey(identityProvider string, kid string) (n *big.Int, e int, err error) {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "GetRSAPublicKey",
			"identityProvider", identityProvider,
			"kid", kid,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.GetRSAPublicKey(identityProvider, kid)
}

func (s *loggingService) GetPKSCache(identityProvider string, pkURL string) (pks *ivmanto.PublicKeySet, err error) {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "GetPKSCache",
			"identityProvider", identityProvider,
			"pkURL", pkURL,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.GetPKSCache(identityProvider, pkURL)
}

func (s *loggingService) DownloadPKSinCache(identityProvider string) {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "DownloadPKSinCache",
			"identityProvider", identityProvider,
			"took", time.Since(begin),
		)
	}(time.Now())
}
