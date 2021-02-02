package authenticating

import (
	"errors"
	"net/http"

	// ivmanto "ivmanto.dev/ivmauth"
	"ivmanto.dev/ivmauth/ivmanto"
)

// ErrInvalidArgument is returned when one or more arguments are invalid.
var ErrInvalidArgument = errors.New("invalid argument")

// Service is the interface that provides auth methods.
type Service interface {
	// RegisterNewRequest registring a new http request for authentication
	RegisterNewRequest(rh http.Header, body []byte) (ivmanto.SessionID, error)

	// Validate the auth request attributes
	Validate(id ivmanto.SessionID) (ivmanto.AccessToken, error)
}

type service struct {
	requests ivmanto.RequestRepository
}

func (s *service) RegisterNewRequest(rh http.Header, body []byte) (ivmanto.SessionID, error) {
	if len(rh) == 0 || len(body) == 0 {
		return "", ErrInvalidArgument
	}

	id := ivmanto.NextSessionID()
	ar := ivmanto.NewAuthRequest(id, rh, body)

	if err := s.requests.Store(ar); err != nil {
		return "", err
	}
	return ar.SessionID, nil
}

func (s *service) Validate(id ivmanto.SessionID) (ivmanto.AccessToken, error) {

	// TODO: compose the correct access token object if validation is successful
	at := ivmanto.AccessToken{}
	return at, nil
}

// NewService creates a authenticating service with necessary dependencies.
func NewService(requests ivmanto.RequestRepository) Service {
	return &service{
		requests: requests,
	}
}
