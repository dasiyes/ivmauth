package authenticating

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-kit/log"
	"github.com/golang-jwt/jwt"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
)

type loggingService struct {
	logger log.Logger
	next   Service
}

// NewLoggingService returns a new instance of a logging Service.
func NewLoggingService(logger log.Logger, s Service) Service {
	return &loggingService{logger, s}
}

func (s *loggingService) Validate(
	rh *http.Header,
	body *core.AuthRequestBody,
	pks pksrefreshing.Service,
	client *core.Client) (at *core.AccessToken, err error) {

	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "validate",
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.Validate(rh, body, pks, client)
}

func (s *loggingService) AuthenticateClient(r *http.Request) (rc *core.Client, err error) {
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

func (s *loggingService) GetRequestBody(r *http.Request) (b *core.AuthRequestBody, err error) {
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

func (s *loggingService) IssueAccessToken(oidt *core.IDToken, client *core.Client) (at *core.AccessToken, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "IssueAccessToken",
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.IssueAccessToken(oidt, client)
}

func (s *loggingService) CheckUserRegistration(oidtoken *core.IDToken) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "CheckUserRegistration",
			"tokenId", oidtoken.Jti,
			"took", time.Since(begin),
		)
	}(time.Now())
}

func (s *loggingService) RegisterUser(names, email, password string) (u *core.User, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "RegisterUser",
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.RegisterUser(names, email, password)
}

func (s *loggingService) UpdateUser(u *core.User) (err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "UpdateUser",
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.next.UpdateUser(u)
}

func (s *loggingService) ValidateUsersCredentials(email, pass string) (ok bool, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "ValidateUsersCredentials",
			"took", time.Since(begin),
			"email", email,
			"password", "",
			"valid", ok,
			"err", err,
		)
	}(time.Now())
	return s.next.ValidateUsersCredentials(email, pass)
}

func (s *loggingService) GetClientsRedirectURI(cid string) (uri []string, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "GetClientsRedirectURI",
			"took", time.Since(begin),
			"clientID", cid,
			"err", err,
		)
	}(time.Now())
	return s.next.GetClientsRedirectURI(cid)
}

func (s *loggingService) IssueIvmIDToken(subCode string, cid core.ClientID) *core.IDToken {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"method", "IssueIvmIDToken",
			"userID", subCode,
			"clientID", cid,
			"took", time.Since(begin),
		)
	}(time.Now())
	return s.next.IssueIvmIDToken(subCode, cid)
}

func (s *loggingService) ValidateAccessToken(at, oidpn string) (tkn *jwt.Token, oidtoken *core.IDToken, err error) {
	defer func(begin time.Time) {
		_ = s.logger.Log(
			"***method***", "ValidateAccessToken",
			"tkn", fmt.Sprintf("%+v", tkn),
			"oidtoken", fmt.Sprintf("%+v", oidtoken),
			"openIDPrvName", oidpn,
			"error", fmt.Sprintf("%v", err),
			"took", time.Since(begin),
		)
	}(time.Now())
	return s.next.ValidateAccessToken(at, oidpn)
}
