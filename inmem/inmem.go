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
