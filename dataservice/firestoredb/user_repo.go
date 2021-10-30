package firestoredb

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/firestore"
	"github.com/dasiyes/ivmauth/core"
	"google.golang.org/api/iterator"
)

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
			return nil, fmt.Errorf("error while convert DataTo user object for %s", doc.Ref.ID)
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
