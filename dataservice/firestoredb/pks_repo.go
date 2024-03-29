package firestoredb

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/firestore"
	"github.com/dasiyes/ivmauth/core"
	"google.golang.org/api/iterator"
)

type publicKeySetRepository struct {
	ctx        *context.Context
	collection string
	client     *firestore.Client
}

// Store - stores the public key set in the firestore DB
func (pksr *publicKeySetRepository) Store(pk *core.PublicKeySet, k *core.KeyRecord) error {

	pks := make(map[string]interface{})
	pks["IdentityProvider"] = pk.IdentityProvider
	pks["URL"] = pk.URL
	pks["Jwks"] = pk.Jwks

	_, err := pksr.client.Collection(pksr.collection).Doc(pk.IdentityProvider).Set(*pksr.ctx, pks)
	if err != nil {
		return fmt.Errorf("unable to save in session repository - error: %v", err)
	}

	if k != nil {
		_, err = pksr.client.Collection("keys-journal").Doc(k.Kid).Set(*pksr.ctx, k)
		if err != nil {
			return fmt.Errorf("unable to save the key in the key-journal")
		}
	}

	return nil
}

// Find - finds a Public Key Set in the repository by provided identity provider name
func (pksr *publicKeySetRepository) Find(ip string) (*core.PublicKeySet, error) {

	if ip == "" {
		return nil, fmt.Errorf("invalid parameter ip value [%s]", ip)
	}
	ip = strings.ToLower(strings.TrimSpace(ip))

	iter := pksr.client.Collection(pksr.collection).Documents(*pksr.ctx)

	var pks core.PublicKeySet

	for {
		doc, err := iter.Next()

		if err == iterator.Done {
			return nil, errors.New("key not found")
		}

		if err != nil {
			if strings.Contains(err.Error(), "Missing or insufficient permissions") {
				return nil, ErrInsufficientPermissions
			} else {
				fmt.Printf("err while iterate firestoreDB: %#v\n", err)
			}
			continue
		}

		var docid = strings.ToLower(strings.TrimSpace(doc.Ref.ID))
		fmt.Printf("[Find] document id normalized value [%s], doc.IP value [%s]\n", docid, pks.IdentityProvider)

		if docid == ip {

			err = doc.DataTo(&pks)
			if err != nil {
				return nil, fmt.Errorf("error %#v, while convert DataTo pks object for %s", err, doc.Ref.ID)
			}

			break
		}

		pks = core.PublicKeySet{}
	}

	return &pks, nil
}

//Find2 - ... alternative methods
func (pksr *publicKeySetRepository) Find2(ip string) (*core.PublicKeySet, error) {

	dsnap, err := pksr.client.Collection(pksr.collection).Doc(ip).Get(*pksr.ctx)
	if err != nil {
		return nil, fmt.Errorf("[Find2] error retrieving documentId %s - error: %#v", ip, err)
	}
	var pk = core.PublicKeySet{}
	err = dsnap.DataTo(&pk)
	if err != nil {
		return nil, fmt.Errorf("error transforming documentId %s - error: %v", ip, err)
	}

	return &pk, nil
}

// FindAll - find and returns all stored Public Key Sets
func (pksr *publicKeySetRepository) FindAll() []*core.PublicKeySet {
	// TODO [dev]: implement FindAll
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
