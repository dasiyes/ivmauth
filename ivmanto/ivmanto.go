// Package ivmanto is the centre of the domain model
package ivmanto

import (
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
	Body       AuthRequestBody
	Registered int64
}

// AuthRequestBody is the json object expected to receive
// in a POST request to /auth path
type AuthRequestBody struct {
	GrantType string `json:"grant_type,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	IDToken   string
	Email     string
	Password  string
	Scopes    []string
	// Session validation token when the GrantType is id_token
	Nonce string
	// This holds the value of the ClientID returned by the Authorization server along with IDToken
	AsrCID string
	// OPTIONAL The name of the Identity provider when the GrantType is id_token
	IDProvider string
}

// NewAuthRequest creates a new, unauthenticated requestor.
func NewAuthRequest(id SessionID, rh http.Header, body AuthRequestBody) *AuthRequest {
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

// NextSessionID generates a new tracking ID.
func NextSessionID() SessionID {
	return SessionID(strings.Split(strings.ToUpper(uuid.New()), "-")[0])
}
