package firestoredb

import (
	"context"
	"fmt"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
	"ivmanto.dev/ivmauth/ivmanto"
)

type requestRepository struct {
	ctx        *context.Context
	collection string
	client     *firestore.Client
}

// Store - stores the authentication request
func (rr *requestRepository) Store(ar *ivmanto.AuthRequest) error {
	_, _, err := rr.client.Collection(rr.collection).Add(*rr.ctx, ar)
	if err != nil {
		return fmt.Errorf("Unable to save in requestRepository. Error: %#v", err)
	}
	return nil
}

// Store - stores the authentication request
func (rr *requestRepository) Find(id ivmanto.SessionID) (*ivmanto.AuthRequest, error) {
	// TODO: implement the logic
	return nil, nil
}

// Store - stores the authentication request
func (rr *requestRepository) FindAll() []*ivmanto.AuthRequest {
	// TODO: implement the logic
	return []*ivmanto.AuthRequest{}
}

// NewRequestRepository returns a new instance of a firestore request repository.
func NewRequestRepository(ctx *context.Context, collName string, client *firestore.Client) (ivmanto.RequestRepository, error) {
	return &requestRepository{
		ctx:        ctx,
		collection: collName,
		client:     client,
	}, nil
}

// Holds the registered cleints
type clientRepository struct {
	ctx        *context.Context
	collection string
	client     *firestore.Client
}

// Store - stores the clients registrations
func (cr *clientRepository) Store(c *ivmanto.Client) error {
	_, err := cr.client.Collection(cr.collection).Doc(string(c.ClientID)).Set(*cr.ctx, c)
	if err != nil {
		return fmt.Errorf("Unable to save in clients Repository. Error: %#v", err)
	}
	return nil
}

// Find - finds a authentication request in the repository
func (cr *clientRepository) Find(id ivmanto.ClientID) (*ivmanto.Client, error) {

	iter := cr.client.Collection(cr.collection).Documents(*cr.ctx)

	var c ivmanto.Client

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			return nil, ErrClientNotFound
		}
		if err != nil {
			continue
		}
		err = doc.DataTo(&c)
		if err != nil {
			continue
		}
		if c.ClientID == id {
			break
		}
	}
	return &c, nil
}

// FindAll - find and returns all authentication request
func (cr *clientRepository) FindAll() []*ivmanto.Client {
	// TODO: implement FindAll
	return []*ivmanto.Client{}
}

// NewClientRepository - creates a new authentication requests repository
func NewClientRepository(ctx *context.Context, collName string, client *firestore.Client) (ivmanto.ClientRepository, error) {
	return &clientRepository{
		ctx:        ctx,
		collection: collName,
		client:     client,
	}, nil
}
