package inmem

import (
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
	// TODO: implement find a response - search by Identity Prodiver (ip string)
	return nil, nil
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
