package firestoredb

import "errors"

var (
	// ErrClientNotFound will be returned when the client is not found in the repository
	ErrClientNotFound = errors.New("client not found")
)
