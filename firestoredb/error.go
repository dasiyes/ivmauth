package firestoredb

import "errors"

var (
	// ErrInsufficientPermissions when the service does not have authorized connection to the DB
	ErrInsufficientPermissions = errors.New("missing or insufficient permissions to read from the DB")

	// ErrClientNotFound will be returned when the client is not found in the repository
	ErrClientNotFound = errors.New("client not found")

	// # USERS

	// ErrUserNotFound is used when a user could not be found.
	ErrUserNotFound = errors.New("user not found")
)
