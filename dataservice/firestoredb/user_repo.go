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

// Store - stores the users' registrations
func (ur *userRepository) Store(u *core.User) error {

	// Using ".Create" instead of ".Set" to avoid overwrite of already saved user with the same email
	_, err := ur.client.Collection(ur.collection).Doc(string(u.UserID)).Create(*ur.ctx, u)
	if err != nil {
		return fmt.Errorf("unable to save in clients repository. error: %v", err)
	}
	return nil
}

// ActivateUser will update the status of user that
func (ur *userRepository) ActivateUserAccount(userId, subCode, state string) error {

	errv := ur.Verify(userId, subCode, state)
	if errv != nil {
		return errv
	}

	_, err := ur.client.Collection(ur.collection).Doc(userId).Update(context.TODO(),
		[]firestore.Update{
			{
				Path:  "Status",
				Value: core.EntryStatusActive,
			},
			{
				Path:  "InitState",
				Value: "Done",
			},
		})
	if err != nil {
		return fmt.Errorf("error while activating user account id %v, err: %v", userId, err)
	}

	fmt.Printf("user %s has been successfully activated\r\n", userId)
	return nil
}

// Exists will check if a user exists in the database
func (ur *userRepository) Exists(userId string) error {

	docusr, err := ur.client.Collection(ur.collection).Doc(userId).Get(context.TODO())
	if err != nil || docusr == nil {
		return fmt.Errorf("document for userId:%s not found", userId)
	}
	return nil
}

// Verify will check if a user exists in the database AND the subCode confirms to match the provided.
// this method will be called before the user account will be activated.
//
// If state is an empty value - the validation will still work for other use cases
func (ur *userRepository) Verify(userId, subCode, state string) error {

	docusr, err := ur.client.Collection(ur.collection).Doc(userId).Get(context.TODO())
	if err != nil || docusr == nil {
		return fmt.Errorf("document for userId:%s not found", userId)
	}
	var u = docusr.Data()
	if u["SubCode"].(string) != subCode {
		return fmt.Errorf("user's subject code: %s doesn't match provided: %s", u["SubCode"].(string), subCode)
	}

	// Only verify the init state if the parameter state is not empty
	if state != "" {
		if u["InitState"].(string) == state && u["Status"].(int64) == int64(core.EntryStatusDraft) {
			return nil
		} else {
			return fmt.Errorf("invalid operation")
		}
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
