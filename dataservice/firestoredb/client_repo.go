package firestoredb

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/firestore"
	"github.com/dasiyes/ivmauth/core"
	"google.golang.org/api/iterator"
)

// Holds the registered cleints
type clientRepository struct {
	ctx        *context.Context
	collection string
	client     *firestore.Client
}

// Store - stores the clients registrations
func (cr *clientRepository) Store(c *core.Client) error {
	_, err := cr.client.Collection(cr.collection).Doc(string(c.ClientID)).Set(*cr.ctx, c)
	if err != nil {
		return fmt.Errorf("unable to save in clients repository. error: %#v", err)
	}
	return nil
}

// Find - finds a client in the repository
func (cr *clientRepository) Find(id core.ClientID) (*core.Client, error) {

	iter := cr.client.Collection(cr.collection).Documents(*cr.ctx)

	var c core.Client

	for {

		doc, err := iter.Next()
		if err == iterator.Done {
			return nil, ErrClientNotFound
		}
		if err != nil {
			if strings.Contains(err.Error(), "Missing or insufficient permissions") {
				return nil, ErrInsufficientPermissions
			} else {
				fmt.Printf("err while iterate firestoreDB: %v", err.Error())
			}
			continue
		}

		err = doc.DataTo(&c)
		if err != nil {
			fmt.Printf("error [doc.DataTo(&c)]: %s\n", err.Error())
			continue
		}

		var findVal = strings.TrimSpace(string(c.ClientID))
		var docVal = strings.TrimSpace(string(id))

		if docVal == findVal {
			break
		}
	}
	return &c, nil
}

// FindAll - find and returns all clients
func (cr *clientRepository) FindAll() []*core.Client {
	// TODO: implement FindAll
	return []*core.Client{}
}

// NewClientRepository - creates a new client repository
func NewClientRepository(ctx *context.Context, collName string, client *firestore.Client) (core.ClientRepository, error) {
	return &clientRepository{
		ctx:        ctx,
		collection: collName,
		client:     client,
	}, nil
}
