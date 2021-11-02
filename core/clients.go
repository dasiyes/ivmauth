package core

import (
	"strings"

	"github.com/pborman/uuid"
)

// ClientID uniquely identifies a particular client.
type ClientID string

// [DOC]
// 2.1 Client Types
//
//    OAuth 2.1 defines three client types based on their ability to
//    authenticate securely with the authorization server as well as the
//    authorization server''s assurance of the client''s identity.
//
//    "confidential":  Clients that have credentials and have a prior
//       relationship with the AS (authorization server) are designated as
//       "confidential clients"
//
//    "credentialed":  Clients that have credentials but no prior
//       relationship with the AS are designated as "credentialed clients"
//
//    "public":  Clients without credentials are called "public clients"
//
//    Any clients with credentials MUST take precautions to prevent leakage
//    and abuse of their credentials.
//
//    Authorization servers SHOULD consider the level of confidence in a
//    client''s identity when deciding whether they allow such a client
//    access to more critical functions, such as the Client Credentials
//    grant type.
//
//    A single client_id MUST NOT be treated as more than one type of
//    client.
//
//    For example, a client that has been registered at the authorization
//    server by a registered application developer, where the client is
//    expected to be run as server-side code, would be considered a
//    confidential client.  A client that runs on an end-user''s device, and
//    uses Dynamic Client Registration ([RFC7591]) to establish credentials
//    the first time the app runs, would be considered a credentialed
//    client.  An application deployed as a single-page app on a static web
//    host would be considered a public client.
//
//    This specification has been designed around the following client
//    profiles:
//
//    "web application":  A web application is a confidential client
//       running on a web server.  Resource owners access the client via an
//       HTML user interface rendered in a user agent on the device used by
//       the resource owner.  The client credentials as well as any access
//       tokens issued to the client are stored on the web server and are
//       not exposed to or accessible by the resource owner.
//
//    "browser-based application":  A browser-based application is a public
//       client in which the client code is downloaded from a web server
//       and executes within a user agent (e.g., web browser) on the device
//       used by the resource owner.  Protocol data and credentials are
//       easily accessible (and often visible) to the resource owner.
//       Since such applications reside within the user agent, they can
//       make seamless use of the user agent capabilities when requesting
//       authorization.
//
//    "native application":  A native application is a public client
//       installed and executed on the device used by the resource owner.
//       Protocol data and credentials are accessible to the resource
//       owner.  It is assumed that any client authentication credentials
//       included in the application can be extracted.  On the other hand,
//       dynamically issued credentials such as access tokens or refresh
//       tokens can receive an acceptable level of protection.  At a
//       minimum, these credentials are protected from hostile servers with
//       which the application may interact.  On some platforms, these
//       credentials might be protected from other applications residing on
//       the same device.

// ClientType according to `The OAuth 2.1 Authorization Framework - section 2.1`
// supported enum values:
// - "confidential"
// - "credentialed"
// - "public"
type ClientType int

const (
	Confidential ClientType = iota
	Credentialed
	Public
)

func (c ClientType) String() string {
	switch c {
	case Confidential:
		return "confidential"
	case Credentialed:
		return "credentialed"
	case Public:
		return "public"
	}
	return ""
}

// EntryStatus describes status of a client registration.
type EntryStatus int

// Valid client statuses.
const (
	Draft EntryStatus = iota
	Active
	NotActive
)

func (s EntryStatus) String() string {
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

// Client is one of the objects for registering or authenticating
type Client struct {
	ClientID      ClientID
	ClientSecret  string
	ClientProfile ClientProfile
	Status        EntryStatus
	Scopes        []string
	RedirectURI   []string
	ClientType    ClientType
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
func NewClient(id ClientID, status EntryStatus) *Client {
	// TODO: write a method to generate the secrets
	// TODO: make the concept for creating and using the scopes for Ivmanto's clients
	profile := ClientProfile{}

	return &Client{
		ClientID:      id,
		ClientSecret:  "",
		ClientProfile: profile,
		Status:        status,
		Scopes:        []string{},
		RedirectURI:   []string{""},
		// Public is the default ClientType, if no other value is provided
		ClientType: Public,
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
