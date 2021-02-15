package ivmanto

import "errors"

var (
	// ErrInvalidIDToken is returned when some of the validation points of IDToken are failing
	ErrInvalidIDToken = errors.New("invalid openId Connect IDToken")
)
