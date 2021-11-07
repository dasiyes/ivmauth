package firestoredb

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/firestore"
	"github.com/dasiyes/ivmauth/core"
)

type publicKeySetRepository struct {
	ctx        *context.Context
	collection string
	client     *firestore.Client
}

// Store - stores the public key set in the firestore DB
func (pksr *publicKeySetRepository) Store(pk *core.PublicKeySet) error {

	pks := make(map[string]interface{})
	pks["IdentityProvider"] = pk.IdentityProvider
	pks["URL"] = pk.URL.String()
	pks["Jwks"] = pk.Jwks

	_, err := pksr.client.Collection(pksr.collection).Doc(pk.IdentityProvider).Set(context.TODO(), pks)
	if err != nil {
		return fmt.Errorf("unable to save in session repository - error: %v", err)
	}

	return nil
}

// Find - finds a Public Key Set in the repository
func (pksr *publicKeySetRepository) Find(ip string) (*core.PublicKeySet, error) {

	return nil, errors.New("key not found")
}

// FindAll - find and returns all stored Public Key Sets
func (pksr *publicKeySetRepository) FindAll() []*core.PublicKeySet {
	// TODO: implement FindAll
	return []*core.PublicKeySet{}
}

// NewPKSRepository - creates a new public key sets repository
func NewPKSRepository(ctx *context.Context, collection string, client *firestore.Client) core.PublicKeySetRepository {
	return &publicKeySetRepository{
		ctx:        ctx,
		collection: collection,
		client:     client,
	}
}
