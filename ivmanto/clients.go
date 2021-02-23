package ivmanto

import (
	"strings"

	"github.com/pborman/uuid"
)

// ClientID uniquely identifies a particular client.
type ClientID string

// Client is one of the objects for registering or authenticating
type Client struct {
	ClientID      ClientID
	ClientSecret  string
	ClientProfile ClientProfile
	Status        ClientStatus
	Scopes        []string
}

// ClientProfile is a client Descriptor
type ClientProfile struct {
	Name             string
	OrganisationName string
	Subscription     Subscription
}

// AssignProfile update a client record with the provided profile
func (c *Client) AssignProfile(p ClientProfile) {

}

// NewClient creates a new client.
func NewClient(id ClientID, status ClientStatus) *Client {
	// TODO: write a method to generate the secrets
	// TODO: make the concept for creating and using the scopes for Ivmanto's clients
	profile := ClientProfile{}

	return &Client{
		ClientID:      id,
		ClientSecret:  "",
		ClientProfile: profile,
		Status:        status,
		Scopes:        []string{},
	}
}

// ClientRepository provides access a client store.
type ClientRepository interface {
	Store(client *Client) error
	Find(id ClientID) (*Client, error)
	FindAll() []*Client
}

// NextClientID generates a new client ID.
func NextClientID(appname string) ClientID {
	return ClientID(strings.Split(strings.ToUpper(uuid.New()), "-")[4] + "-" + appname + "-" + "ivmanto.dev")
}

// ClientStatus describes status of a client registration.
type ClientStatus int

// Valid client statuses.
const (
	Draft ClientStatus = iota
	Active
	NotActive
)

func (s ClientStatus) String() string {
	switch s {
	case Draft:
		return "Draft"
	case Active:
		return "Active"
	case NotActive:
		return "NotActive"
	}
	return ""
}
