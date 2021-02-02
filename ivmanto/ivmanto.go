// Package ivmanto is the centre of the domain model
package ivmanto

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pborman/uuid"
)

// SessionID uniquely identifies an auth session.
type SessionID string

// AuthRequest is the central class in the domain model.
type AuthRequest struct {
	SessionID  SessionID
	ReqHeaders http.Header
	Body       []byte
	Registered int64
}

// NewAuthRequest creates a new, unauthenticated requestor.
func NewAuthRequest(id SessionID, rh http.Header, body []byte) *AuthRequest {
	rs := time.Now().Unix()
	return &AuthRequest{
		SessionID:  id,
		ReqHeaders: rh,
		Body:       body,
		Registered: rs,
	}
}

// RequestRepository provides access to a requests store.
type RequestRepository interface {
	Store(authreq *AuthRequest) error
	Find(id SessionID) (*AuthRequest, error)
	FindAll() []*AuthRequest
}

// ErrUnknownGrantType is used when could not be find grant-type attribute.
var ErrUnknownGrantType = errors.New("unknown grant type")

// ErrInvalidArgument is used when some of the required arguments is missing or wrong
var ErrInvalidArgument = errors.New("invalid argument")

// NextSessionID generates a new tracking ID.
func NextSessionID() SessionID {
	return SessionID(strings.Split(strings.ToUpper(uuid.New()), "-")[0])
}
