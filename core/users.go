package core

import (
	"github.com/rs/xid"
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
	Password     []byte      `json:"-"`
	Avatar       string      `json:"-"`
	Status       EntryStatus `json:"-"`
	OIDCProvider string
	SubCode      SubCode `json:"-"`
	RefreshToken string  `json:"-"`
	// InitState is the attribute to use as verification attribute when the user activate its account. Effectively the value of the session id when registering the new user and value `Done` when the user has been activated or is signed up by third party OpenID provider.
	InitState string `json:"-"`
	Created   int64
}

// UpdateRefreshToken updates the Refresh Token for the user
func (u *User) UpdateRefreshToken(rt string) {
	if rt != "" {
		u.RefreshToken = rt
	}
}

// UserRepository provides access to the users storage.
type UserRepository interface {
	Store(user *User) error
	ActivateUserAccount(userId, subCode, state string) error
	Exists(userId string) error
	Verify(userId, subCode, state string) error
	Find(id UserID) (*User, error)
	FindBySubjectCode(sc string) (*User, error)
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
	return SubCode(xid.New().String())
}
