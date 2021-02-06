package inmem

import (
	"errors"
	"sync"

	"ivmanto.dev/ivmauth/ivmanto"
)

type requestRepository struct {
	mtx      sync.RWMutex
	requests map[ivmanto.SessionID]*ivmanto.AuthRequest
}

// Store - stores the authentication request
func (rr *requestRepository) Store(ar *ivmanto.AuthRequest) error {
	rr.mtx.Lock()
	defer rr.mtx.Unlock()
	rr.requests[ar.SessionID] = ar
	return nil
}

// Find - finds a authentication request in the repository
func (rr *requestRepository) Find(id ivmanto.SessionID) (*ivmanto.AuthRequest, error) {
	// TODO: implement find a response
	return nil, nil
}

// FindAll - find and returns all authentication request
func (rr *requestRepository) FindAll() []*ivmanto.AuthRequest {
	// TODO: implement FindAll
	return []*ivmanto.AuthRequest{}
}

// NewRequestRepository - creates a new authentication requests repository
func NewRequestRepository() ivmanto.RequestRepository {
	return &requestRepository{
		requests: make(map[ivmanto.SessionID]*ivmanto.AuthRequest),
	}
}

type publicKeySetRepository struct {
	mtx sync.RWMutex
	pks map[string]*ivmanto.PublicKeySet
}

// Store - stores the public key set for the cache-time allowed in Cache-Control Header
func (pksr *publicKeySetRepository) Store(pk *ivmanto.PublicKeySet) error {
	pksr.mtx.Lock()
	defer pksr.mtx.Unlock()
	pksr.pks[pk.IdentityProvider] = pk
	return nil
}

// Find - finds a Public Key Set in the repository
func (pksr *publicKeySetRepository) Find(ip string) (*ivmanto.PublicKeySet, error) {
	for key, pks := range pksr.pks {
		if key == ip {
			return pks, nil
		}
	}
	return nil, errors.New("key not found")
}

// FindAll - find and returns all stored Public Key Sets
func (pksr *publicKeySetRepository) FindAll() []*ivmanto.PublicKeySet {
	// TODO: implement FindAll
	return []*ivmanto.PublicKeySet{}
}

// NewPKSRepository - creates a new public key sets repository
func NewPKSRepository() ivmanto.PublicKeySetRepository {
	return &publicKeySetRepository{
		pks: make(map[string]*ivmanto.PublicKeySet),
	}
}

// Holds the registered cleints
type clientRepository struct {
	mtx     sync.RWMutex
	clients map[ivmanto.ClientID]*ivmanto.Client
}

// Store - stores the clients registrations
func (cr *clientRepository) Store(c *ivmanto.Client) error {
	cr.mtx.Lock()
	defer cr.mtx.Unlock()
	cr.clients[c.ClientID] = c
	return nil
}

// Find - finds a authentication request in the repository
func (cr *clientRepository) Find(id ivmanto.ClientID) (*ivmanto.Client, error) {
	// TODO: implement find a response
	return nil, nil
}

// FindAll - find and returns all authentication request
func (cr *clientRepository) FindAll() []*ivmanto.Client {
	// TODO: implement FindAll
	return []*ivmanto.Client{}
}

// NewClientRepository - creates a new authentication requests repository
func NewClientRepository() ivmanto.ClientRepository {
	return &clientRepository{
		clients: make(map[ivmanto.ClientID]*ivmanto.Client),
	}
}
