package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

var (
	// # GENERAL

	// ErrInvalidArgument is used when some of the required arguments is missing or wrong
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrGetRequestBody is returned when reading the request body
	ErrGetRequestBody = errors.New("error reading request body")

	// # AUTHENTICATION

	// ErrBadRequest is returned when the request does not pass the expected configuration
	ErrBadRequest = errors.New("bad request")

	// ErrInvalidIDToken is returned when some of the validation points of IDToken are failing
	ErrInvalidIDToken = errors.New("invalid openId Connect IDToken")

	// ErrUnknownGrantType is used when could not be find grant-type attribute.
	ErrUnknownGrantType = errors.New("unknown grant type")

	// ErrClientAuth is returned when client Basic authentication fails
	ErrClientAuth = errors.New("invalid client authentication credentials")

	// ErrAuthenticating is returned when the authentication process fails
	ErrAuthenticating = errors.New("authentication failed")

	// ErrTLS - returned when the content-type is set to "application/x-www-form-urlencoded" and no TLS is used
	ErrTLS = errors.New("unsecured transport of credentials")

	// ErrSessionToken - when the NONCE value from the IDToken does not match the value sent from the client in the auth request body
	ErrSessionToken = errors.New("invalid session token")

	// ErrCompromisedAud - will be returned when the valid of the ClientID returned to the client from the authorization server alongside with the IDToken, does not match the aud value in the IDToken
	ErrCompromisedAud = errors.New("compromised audience")

	// ErrUnknownClient is used when a client could not be found.
	ErrUnknownClient = errors.New("unknown client")

	// ErrInvalidPubliKeySet is used when new key fails to update PublicKeySet.
	ErrInvalidPubliKeySet = errors.New("invalid public key set")

	// ErrUnknownMethod is used when during Access Token generation the signing method is not defined
	ErrUnknownMethod = errors.New("unknown signing method")

	// ErrIssuingAT is used when the issue of the Access Token has failed.
	ErrIssuingAT = errors.New("error generating access token")
)

const (
	// # InternalErrorCode

	// IntErrAuth Error codes in failling auth operations
	IntErrAuth int = 999 + 1<<iota

	// IntErrClientAuth failling operations in client auth
	IntErrClientAuth
)

// InvalidPubliKeySet is used when new key fails to update PublicKeySet.
func InvalidPublicKeySet(err error) error {
	if err != nil {
		return errors.New("invalid public key set: " + err.Error())
	}
	return ErrInvalidPubliKeySet
}

// TODO: Completely refactor this method... SHOULD return JSON response easy and fast!

// EncodeError - responses to http requests with error
func EncodeError(_ context.Context, rs int, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if rs > 100 && rs < 599 {
		switch rs {
		case http.StatusUnauthorized:
			w.Header().Set("WWW-Authenticate", "Newauth realm\"ivmanto\"")
		}
		w.WriteHeader(rs)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"errorCode": rs, "error": err.Error(),
	})
}
