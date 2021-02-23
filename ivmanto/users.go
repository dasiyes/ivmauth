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
	subCode  SubCode
	profile  userProfile
	verified bool

	UserID   UserID `json:"email"`
	Name     string
	Password string
	Avatar   string
	Status   UserStatus
}

// UserRepository provides access to the users storage.
type UserRepository interface {
	Store(client *User) error
	Find(id UserID) (*User, error)
	FindAll() []*User
}

// NewUser creates a new object User
func NewUser(is UserID) (*User, error) {

	return nil, nil
}

// userProfile to hold the application related and authrozation attributes
// to be extended
type userProfile struct {
	scope []string
}

// UserStatus defines the state of the user in the system
type UserStatus int

const (
	// Draft - user status for new, pending verification users
	Draft UserStatus = iota
	// Active - user status for normal users state
	Active
	// NotActive - user status to fall into when the users once has been activated
	NotActive
)

func (u UserStatus) String() string {
	switch u {
	case Draft:
		return "Draft"
	case Active:
		return "Active"
	case NotActive:
		return "NotActive"
	default:
		return ""
	}
}

// NewSubCode generates a new subject code value.
func NewSubCode() SubCode {
	return SubCode(strings.ToUpper(string(uuid.NodeID())))
}
