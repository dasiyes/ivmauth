package ivmanto

import "errors"

// UNLocode is the United Nations location code that uniquely identifies a
// particular location.
//
// http://www.unece.org/cefact/locode/
// http://www.unece.org/cefact/locode/DocColumnDescription.htm#LOCODE
type UNLocode string

// Location is a location in our model from where a requestor has started
// the request for authentication to the endpoint /auth.
type Location struct {
	UNLocode UNLocode
	Name     string
}

// ErrUnknownLocation is used when a location could not be found.
var ErrUnknownLocation = errors.New("unknown location")

// LocationRepository provides access a location store.
type LocationRepository interface {
	Find(locode UNLocode) (*Location, error)
	FindAll() []*Location
}
