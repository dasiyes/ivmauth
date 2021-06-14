// Package ivmanto is the centre of the domain model
package ivmanto

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/pborman/uuid"
)

// AuthRequestID uniquely identifies an auth session.
type AuthRequestID string

// AuthRequest is the central class in the domain model.
type AuthRequest struct {
	AuthRequestID AuthRequestID
	ReqHeaders    http.Header
	Body          AuthRequestBody
	Client        Client
	Registered    int64
}

// AuthRequestBody is the json object expected to receive
// in a POST request to /auth path
type AuthRequestBody struct {
	GrantType string `json:"grant_type,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	IDToken   string
	Name      string
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
func NewAuthRequest(id AuthRequestID, rh http.Header, body *AuthRequestBody, client *Client) *AuthRequest {
	rs := time.Now().Unix()
	return &AuthRequest{
		AuthRequestID: id,
		ReqHeaders:    rh,
		Body:          *body,
		Client:        *client,
		Registered:    rs,
	}
}

// RequestRepository provides access to a requests store.
type RequestRepository interface {
	Store(authreq *AuthRequest) error
	Find(id AuthRequestID) (*AuthRequest, error)
	FindAll() []*AuthRequest
}

// NextAuthRequestID generates a new tracking ID.
func NextAuthRequestID() AuthRequestID {
	return AuthRequestID(strings.Split(strings.ToUpper(uuid.New()), "-")[4])
}

// Generate a new token ID
func genTID(realm string) string {

	// newS := strings.Split(strings.ToUpper(uuid.New()), "-")[4]
	newS := realm
	// TODO: possibly generating ns may cause issues with multiple go routines. Consider moving it to a config/db value
	ns := rand.NewSource(int64(47))
	r2 := rand.New(ns)
	src := []byte(newS + fmt.Sprintf("%d", *r2))
	dst := make([]byte, hex.EncodedLen(len(src)))
	_ = hex.Encode(dst, src)
	return string(dst)
}
