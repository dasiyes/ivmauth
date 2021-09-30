package firestoredb

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/firestore"
	"github.com/dasiyes/ivmauth/core"
	"google.golang.org/api/iterator"
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

	// TODO: remove after debug
	fmt.Printf("... search for clientID %v\n", id)
	var cnt = 0

	for {

		// TODO: remove after debug
		fmt.Printf("counter: %d\n\n", cnt)

		doc, err := iter.Next()
		cnt++
		if err == iterator.Done {
			fmt.Printf("error [Done]: %s\n", err.Error())
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

		// TODO: remove after debug
		fmt.Printf("doc.Ref.ID: %v, c.ClientID: %v, find id: %v\n", doc.Ref.ID, c.ClientID, id)
		fmt.Printf("c.ClientID: %s\n", docVal)
		fmt.Printf("id: %s\n", findVal)

		if strings.Compare(docVal, findVal) == 0 {
			fmt.Printf("equal? - TRUE")
			break
		} else {
			fmt.Printf("the difference is: %d", strings.Compare(docVal, findVal))
			fmt.Printf("docVal[byte] : %v\n", []byte(docVal))
			fmt.Printf("findVal[byte]: %v\n", []byte(findVal))
			fmt.Printf("c: %v, docVal: %s, findVal: %s", c, docVal, findVal)
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

// Holds the registered users
type userRepository struct {
	ctx        *context.Context
	collection string
	client     *firestore.Client
}

// Store - stores the clients registrations
func (ur *userRepository) Store(u *core.User) error {
	_, err := ur.client.Collection(ur.collection).Doc(string(u.UserID)).Set(*ur.ctx, u)
	if err != nil {
		return fmt.Errorf("unable to save in clients repository. error: %#v", err)
	}
	return nil
}

// Find - finds a user in the repository
func (ur *userRepository) Find(id core.UserID) (*core.User, error) {

	iter := ur.client.Collection(ur.collection).Documents(*ur.ctx)

	var u core.User

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			return nil, ErrUserNotFound
		}
		if err != nil {
			if strings.Contains(err.Error(), "Missing or insufficient permissions") {
				return nil, ErrInsufficientPermissions
			} else {
				fmt.Printf("err while iterate firestoreDB: %v", err.Error())
			}
			continue
		}

		err = doc.DataTo(&u)
		if err != nil {
			return nil, err
			// TODO: review the error for missing permissions
			//continue
		}
		if core.UserID(doc.Ref.ID) == id {
			break
		}
		u = core.User{}
	}
	return &u, nil
}

// FindAll - find and returns all users
func (ur *userRepository) FindAll() []*core.User {
	// TODO: implement FindAll
	return []*core.User{}
}

// NewUserRepository - creates a new users repository
func NewUserRepository(ctx *context.Context, collName string, client *firestore.Client) (core.UserRepository, error) {
	return &userRepository{
		ctx:        ctx,
		collection: collName,
		client:     client,
	}, nil
}
