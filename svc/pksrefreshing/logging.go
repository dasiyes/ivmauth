package pksrefreshing

import (
	"math/big"
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

func (s *loggingService) InitOIDProviders(oidps []string) (errs []error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "InitOIDProviders",
			"took", time.Since(begin),
			"errors_raised", len(errs),
		)
	}(time.Now())
	return s.next.InitOIDProviders(oidps)
}

func (s *loggingService) GetRSAPublicKey(identityProvider string, kid string) (n *big.Int, e int, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "GetRSAPublicKey",
			"identityProvider", identityProvider,
			"kid", kid,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.GetRSAPublicKey(identityProvider, kid)
}

func (s *loggingService) GetPKSCache(identityProvider string) (pks *core.PublicKeySet, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "GetPKSCache",
			"identityProvider", identityProvider,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.GetPKSCache(identityProvider)
}

// func (s *loggingService) DownloadPKSinCache(identityProvider string) (err error) {
// 	defer func(begin time.Time) {
// 		_ = s.logger.Log(
// 			"method", "DownloadPKSinCache",
// 			"identityProvider", identityProvider,
// 			"took", time.Since(begin),
// 			"error", err,
// 		)
// 	}(time.Now())
// 	return s.next.DownloadPKSinCache(identityProvider)
// }

func (s *loggingService) GetIssuerVal(provider string) (iss string, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "GetIssuerVal",
			"identityProvider", provider,
			"issuer", iss,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.GetIssuerVal(provider)
}

func (s *loggingService) PKSRotator() (err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "PKSRotator",
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.PKSRotator()
}
