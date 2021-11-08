package firestoredb

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/firestore"
	"github.com/dasiyes/ivmauth/core"
)

// Holds the registered OpenID Providers
type oidProviderRepository struct {
	ctx        *context.Context
	collection string
	client     *firestore.Client
}

// Store - stores the provider registrations
func (ip *oidProviderRepository) Store(pr *core.OIDProvider) error {

	_, err := ip.client.Collection(ip.collection).Doc(string(pr.ProviderName)).Set(context.TODO(), pr)
	if err != nil {
		return fmt.Errorf("unable to save in session repository - error: %v", err)
	}

	return nil
}

// Find - finds a authentication request in the repository
func (ip *oidProviderRepository) Find(pr core.ProviderName) (*core.OIDProvider, error) {

	return nil, errors.New("provider not found")
}

// FindAll - find and returns all authentication request
func (ip *oidProviderRepository) FindAll() []*core.OIDProvider {
	// TODO: implement FindAll
	return []*core.OIDProvider{}
}

// NewOIDProviderRepository - creates a new OpenID Providers repository
func NewOIDProviderRepository(ctx *context.Context, collection string, client *firestore.Client) core.OIDProviderRepository {
	return &oidProviderRepository{
		ctx:        ctx,
		collection: collection,
		client:     client,
	}
}
