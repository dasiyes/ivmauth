package inmem

import (
	"errors"
	"sync"

	"github.com/dasiyes/ivmauth/core"
)

type requestRepository struct {
	mtx      sync.RWMutex
	requests map[core.AuthRequestID]*core.AuthRequest
}

// Store - stores the authentication request
func (rr *requestRepository) Store(ar *core.AuthRequest) error {
	rr.mtx.Lock()
	defer rr.mtx.Unlock()
	rr.requests[ar.AuthRequestID] = ar
	return nil
}

// Find - finds a authentication request in the repository
func (rr *requestRepository) Find(id core.AuthRequestID) (*core.AuthRequest, error) {
	// TODO: implement find a response
	return nil, nil
}

// FindAll - find and returns all authentication request
func (rr *requestRepository) FindAll() []*core.AuthRequest {
	// TODO: implement FindAll
	return []*core.AuthRequest{}
}

// NewRequestRepository - creates a new authentication requests repository
func NewRequestRepository() core.RequestRepository {
	return &requestRepository{
		requests: make(map[core.AuthRequestID]*core.AuthRequest),
	}
}

type publicKeySetRepository struct {
	mtx sync.RWMutex
	pks map[string]*core.PublicKeySet
}

// Store - stores the public key set for the cache-time allowed in Cache-Control Header
func (pksr *publicKeySetRepository) Store(pk *core.PublicKeySet) error {
	pksr.mtx.Lock()
	defer pksr.mtx.Unlock()
	pksr.pks[pk.IdentityProvider] = pk
	return nil
}

// Find - finds a Public Key Set in the repository
func (pksr *publicKeySetRepository) Find(ip string) (*core.PublicKeySet, error) {
	for key, pks := range pksr.pks {
		if key == ip {
			return pks, nil
		}
	}
	return nil, errors.New("key not found")
}

// FindAll - find and returns all stored Public Key Sets
func (pksr *publicKeySetRepository) FindAll() []*core.PublicKeySet {
	// TODO: implement FindAll
	return []*core.PublicKeySet{}
}

// NewPKSRepository - creates a new public key sets repository
func NewPKSRepository() core.PublicKeySetRepository {
	return &publicKeySetRepository{
		pks: make(map[string]*core.PublicKeySet),
	}
}

// Holds the registered cleints
type clientRepository struct {
	mtx     sync.RWMutex
	clients map[core.ClientID]*core.Client
}

// Store - stores the clients registrations
func (cr *clientRepository) Store(c *core.Client) error {
	cr.mtx.Lock()
	defer cr.mtx.Unlock()
	cr.clients[c.ClientID] = c
	return nil
}

// Find - finds a authentication request in the repository
func (cr *clientRepository) Find(id core.ClientID) (*core.Client, error) {
	for clientID, client := range cr.clients {
		if clientID == id {
			return client, nil
		}
	}
	return nil, errors.New("client not found")
}

// FindAll - find and returns all authentication request
func (cr *clientRepository) FindAll() []*core.Client {
	// TODO: implement FindAll
	return []*core.Client{}
}

// NewClientRepository - creates a new authentication requests repository
func NewClientRepository() core.ClientRepository {
	return &clientRepository{
		clients: make(map[core.ClientID]*core.Client),
	}
}

// Holds the registered OpenID Providers
type oidProviderRepository struct {
	mtx       sync.RWMutex
	providers map[core.ProviderName]*core.OIDProvider
}

// Store - stores the provider registrations
func (ip *oidProviderRepository) Store(pr *core.OIDProvider) error {
	ip.mtx.Lock()
	defer ip.mtx.Unlock()
	ip.providers[pr.ProviderName] = pr
	return nil
}

// Find - finds a authentication request in the repository
func (ip *oidProviderRepository) Find(pr core.ProviderName) (*core.OIDProvider, error) {
	for prvname, oidp := range ip.providers {
		if prvname == pr {
			return oidp, nil
		}
	}
	return nil, errors.New("provider not found")
}

// FindDeadline - only valid for Ivmanto's provider. The dealine defines the PublicKey rotation period.
func (pksr *publicKeySetRepository) FindDeadline(kid string) (dl int64, err error) {
	// TODO [dev]: implement the same logic as it is in pks_repo.go
	return dl, nil
}

// FindAll - find and returns all authentication request
func (ip *oidProviderRepository) FindAll() []*core.OIDProvider {
	// TODO: implement FindAll
	return []*core.OIDProvider{}
}

// NewOIDProviderRepository - creates a new OpenID Providers repository
func NewOIDProviderRepository() core.OIDProviderRepository {
	return &oidProviderRepository{
		providers: make(map[core.ProviderName]*core.OIDProvider),
	}
}

// Holds the registered users
type userRepository struct {
	mtx   sync.RWMutex
	users map[core.UserID]*core.User
}

// Store - stores the clients registrations
func (ur *userRepository) Store(u *core.User) error {
	ur.mtx.Lock()
	defer ur.mtx.Unlock()
	ur.users[u.UserID] = u
	return nil
}

// Find - finds a authentication request in the repository
func (ur *userRepository) Find(id core.UserID) (*core.User, error) {
	for userID, user := range ur.users {
		if userID == id {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

// FindAll - find and returns all authentication request
func (ur *userRepository) FindAll() []*core.User {
	// TODO: implement FindAll
	return []*core.User{}
}

// NewUserRepository - creates a new users repository
func NewUserRepository() core.UserRepository {
	return &userRepository{
		users: make(map[core.UserID]*core.User),
	}
}
