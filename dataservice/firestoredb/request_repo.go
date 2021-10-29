package firestoredb

import (
	"context"
	"fmt"

	"cloud.google.com/go/firestore"
	"github.com/dasiyes/ivmauth/core"
)

type requestRepository struct {
	ctx        *context.Context
	collection string
	client     *firestore.Client
}

// Store - stores the authentication request
func (rr *requestRepository) Store(ar *core.AuthRequest) error {
	_, _, err := rr.client.Collection(rr.collection).Add(*rr.ctx, ar)
	if err != nil {
		return fmt.Errorf("unable to save in request repository. Error: %#v", err)
	}
	return nil
}

// Store - stores the authentication request
func (rr *requestRepository) Find(id core.AuthRequestID) (*core.AuthRequest, error) {
	// TODO: implement the logic
	return nil, nil
}

// Store - stores the authentication request
func (rr *requestRepository) FindAll() []*core.AuthRequest {
	// TODO: implement the logic
	return []*core.AuthRequest{}
}

// NewRequestRepository returns a new instance of a firestore request repository.
func NewRequestRepository(ctx *context.Context, collName string, client *firestore.Client) (core.RequestRepository, error) {
	return &requestRepository{
		ctx:        ctx,
		collection: collName,
		client:     client,
	}, nil
}
