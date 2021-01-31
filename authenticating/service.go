package authenticating

import (
	"errors"

	ivmanto "ivmanto.dev/ivmauth"
)

// ErrInvalidArgument is returned when one or more arguments are invalid.
var ErrInvalidArgument = errors.New("invalid argument")

// Service is the interface that provides auth methods.
type Service interface {
	// LogNewRequest registring a new http request for authentication
	LogNewRequest() (ivmanto.TrackingID, error)

	// Validate the auth request attributes
	Validate(ivmanto.RequestSpec) (ivmanto.AccessToken, error)
}

type service struct {
	RequestSpec ivmanto.RequestSpec
}

func (s *service) LogNewRequest() (ivmanto.TrackingID, error) {
	if s.RequestSpec.Body == nil {
		return "", ErrInvalidArgument
	}
	// TODO: check the spec if required data are IN...
	tid := ivmanto.NextTrackingID()
	return tid, nil
}

func (s *service) Validate() ivmanto.AccessToken {

	// TODO: compose the correct access token object if validation is successful
	at := ivmanto.AccessToken{}
	return at
}
