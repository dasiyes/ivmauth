package authenticating

import (
	"errors"
	"net/http"

	ivmanto "ivmanto.dev/ivmauth"
	"ivmanto.dev/ivmauth/ivmanto"
)

// ErrInvalidArgument is returned when one or more arguments are invalid.
var ErrInvalidArgument = errors.New("invalid argument")

// Service is the interface that provides auth methods.
type Service interface {
	// RegisterNewRequest registring a new http request for authentication
	RegisterNewRequest() (ivmanto.TrackingID, error)

	// Validate the auth request attributes
	Validate(ivmanto.RequestSpec) (ivmanto.AccessToken, error)
}

type service struct {
	AuthRequest ivmanto.AuthRequest
}

func (s *service) RegisterNewRequest(rh http.Header, body []byte) (ivmanto.SessionID, error) {
	if len(rh) == 0 || len(body) == 0 {
		return "", ErrInvalidArgument
	}

	id := ivmanto.NextSessionID()
	ar := ivmanto.AuthRequest{
		SessionID:  id,
		ReqHeaders: rh,
		Body:       body,
	}

	c := ivmanto.NewAuthRequest(id, rh, body)

	if err := s.cargos.Store(c); err != nil {
		return "", err
	}

	return c.TrackingID, nil
}

func (s *service) Validate() (ivmanto.AccessToken, error) {

	// TODO: compose the correct access token object if validation is successful
	at := ivmanto.AccessToken{}
	return at, nil
}
