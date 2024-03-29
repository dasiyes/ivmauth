package firestoredb

import (
	"context"
	"fmt"

	"cloud.google.com/go/firestore"
	"github.com/dasiyes/ivmauth/core"
)

type keysJournalRepo struct {
	ctx        *context.Context
	collection string
	client     *firestore.Client
}

// AddKey will store the new issued key pairs in the Journal repo
func (kj *keysJournalRepo) AddKey(k *core.KeyRecord) error {

	if k == nil {
		return fmt.Errorf("invalid key record parameter")
	}

	_, err := kj.client.Collection(kj.collection).Doc(k.Kid).Set(context.TODO(), k)
	if err != nil {
		return fmt.Errorf("failed to add new key [id: %s] - error: %v", k.Kid, err)
	}

	return nil
}

// FindDeadline is browse the repo for a given key id and return its deadline (expire date)
func (kj *keysJournalRepo) FindDeadline(kid string) (dl int64, err error) {

	if kid == "" {
		return 0, fmt.Errorf("[FindDeadline] missing mandatory argument kid [%s]", kid)
	}

	dsnap, err := kj.client.Collection(kj.collection).Doc(kid).Get(*kj.ctx)
	if err != nil {
		return 0, fmt.Errorf("[FindDeadline] error retrieving documentId %s - error: %v", kid, err)
	}
	var kr = core.KeyRecord{}
	err = dsnap.DataTo(&kr)
	if err != nil {
		return 0, fmt.Errorf("[FindDeadline] error transforming documentId %s - error: %v", kid, err)
	}

	dl = kr.Deadline

	return dl, nil
}

// GetSigningKey will return the private key required for signing operations
func (kj *keysJournalRepo) GetSigningKey(kid string) (pk string, err error) {

	if kid == "" {
		return "", fmt.Errorf("[GetSigningKey] missing mandatory argument kid [%s]", kid)
	}

	dsnap, err := kj.client.Collection(kj.collection).Doc(kid).Get(*kj.ctx)
	if err != nil {
		return "", fmt.Errorf("[GetSigningKey] error retrieving documentId %s - error: %v", kid, err)
	}
	var kr = core.KeyRecord{}
	err = dsnap.DataTo(&kr)
	if err != nil {
		return "", fmt.Errorf("[GetSigningKey] error transforming documentId %s - error: %v", kid, err)
	}

	return kr.PrivateKey, nil
}

func NewKeysJournalRepo(ctx *context.Context, collectionName string, client *firestore.Client) core.KJR {

	return &keysJournalRepo{
		ctx:        ctx,
		collection: collectionName,
		client:     client,
	}

}
