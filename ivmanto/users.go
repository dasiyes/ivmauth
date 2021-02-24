package ivmanto

import (
	"strings"

	"github.com/google/uuid"
)

// UserID uniquely identifies a particular client.
type UserID string

// SubCode is a random code to be used for subject id in the access token claims. In combination with the userID (email ) shoud uniquely identify the user.
type SubCode string

// User object in the realm Ivmanto
type User struct {
	profile  userProfile
	verified bool

	UserID       UserID `json:"email"`
	Name         string
	Password     string
	Avatar       string
	Status       EntryStatus
	OIDCProvider string
	SubCode      SubCode
}

// UserRepository provides access to the users storage.
type UserRepository interface {
	Store(user *User) error
	Find(id UserID) (*User, error)
	FindAll() []*User
}

// NewUser creates a new object User
func NewUser(is UserID) (*User, error) {
	sc := NewSubCode()

	return &User{
		profile: userProfile{
			scope: []string{},
		},
		verified: false,
		UserID:   is,
		SubCode:  sc,
	}, nil
}

// userProfile to hold the application related and authrozation attributes
// to be extended
type userProfile struct {
	scope []string
}

// NewSubCode generates a new subject code value.
func NewSubCode() SubCode {
	return SubCode(strings.ToUpper(string(uuid.NodeID())))
}
