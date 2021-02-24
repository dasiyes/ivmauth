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

// Find - finds a client in the repository
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

// FindAll - find and returns all clients
func (cr *clientRepository) FindAll() []*ivmanto.Client {
	// TODO: implement FindAll
	return []*ivmanto.Client{}
}

// NewClientRepository - creates a new client repository
func NewClientRepository(ctx *context.Context, collName string, client *firestore.Client) (ivmanto.ClientRepository, error) {
	return &clientRepository{
		ctx:        ctx,
		collection: collName,
		client:     client,
	}, nil
}

// Holds the registered users
type userRepository struct {
	ctx        *context.Context
	collection string
	client     *firestore.Client
}

// Store - stores the clients registrations
func (ur *userRepository) Store(u *ivmanto.User) error {
	_, err := ur.client.Collection(ur.collection).Doc(string(u.UserID)).Set(*ur.ctx, u)
	if err != nil {
		return fmt.Errorf("Unable to save in clients Repository. Error: %#v", err)
	}
	return nil
}

// Find - finds a user in the repository
func (ur *userRepository) Find(id ivmanto.UserID) (*ivmanto.User, error) {

	iter := ur.client.Collection(ur.collection).Documents(*ur.ctx)

	var u ivmanto.User

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			return nil, ErrUserNotFound
		}
		if err != nil {
			return nil, err
			//continue
		}
		err = doc.DataTo(&u)
		if err != nil {
			return nil, err
			//continue
		}
		if u.UserID == id {
			break
		}
	}
	return &u, nil
}

// FindAll - find and returns all users
func (ur *userRepository) FindAll() []*ivmanto.User {
	// TODO: implement FindAll
	return []*ivmanto.User{}
}

// NewUserRepository - creates a new users repository
func NewUserRepository(ctx *context.Context, collName string, client *firestore.Client) (ivmanto.UserRepository, error) {
	return &userRepository{
		ctx:        ctx,
		collection: collName,
		client:     client,
	}, nil
}
