// Package ivmanto is the centre of the domain model
package ivmanto

import (
	"errors"
	"strings"

	"github.com/pborman/uuid"
)

// TrackingID uniquely identifies an auth session.
type TrackingID string

// Requestor is the central class in the domain model.
type Requestor struct {
	TrackingID   TrackingID
	Origin       UNLocode
	RequestSpec  RequestSpec
	Profile      Profile
	AccessToken  AccessToken
	Subscription Subscription
}

// TODO: Complete with all methods for a Requestor

// NewRequestor creates a new, unauthenticated requestor.
func NewRequestor(id TrackingID, rs RequestSpec) *Requestor {

	return &Requestor{
		TrackingID:  id,
		Origin:      rs.Location,
		RequestSpec: rs,
	}
}

// RequestorRepository provides access to a requests store.
type RequestorRepository interface {
	Store(cargo *Requestor) error
	Find(id TrackingID) (*Requestor, error)
	FindAll() []*Requestor
}

// ErrUnknownGrantType is used when could not be find grant-type attribute.
var ErrUnknownGrantType = errors.New("unknown grant type")

// ErrInvalidArgument is used when some of the required arguments is missing or wrong
var ErrInvalidArgument = errors.New("invalid argument")

// NextTrackingID generates a new tracking ID.
// TODO: Move to infrastructure(?)
func NextTrackingID() TrackingID {
	return TrackingID(strings.Split(strings.ToUpper(uuid.New()), "-")[0])
}
