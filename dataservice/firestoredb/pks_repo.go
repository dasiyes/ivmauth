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
	}

	return nil
}

// Find - finds a Public Key Set in the repository
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

// FindDeadline - only valid for Ivmanto's provider. The dealine defines the PublicKey rotation period.
// func (pksr *publicKeySetRepository) FindDeadline(kid string) (dl int64, err error) {
//
// 	if kid == "" {
// 		return 0, fmt.Errorf("invalid parameter kid value [%s]", kid)
// 	}
//
// 	var ip = "ivmanto"
//
// 	iter := pksr.client.Collection(pksr.collection).Documents(*pksr.ctx)
//
// 	var pks core.PublicKeySet
//
// 	for {
// 		doc, err := iter.Next()
//
// 		if err == iterator.Done {
// 			return 0, errors.New("key not found")
// 		}
//
// 		if err != nil {
// 			if strings.Contains(err.Error(), "Missing or insufficient permissions") {
// 				return 0, ErrInsufficientPermissions
// 			} else {
// 				fmt.Printf("err while iterate firestoreDB: %#v", err)
// 			}
// 			continue
// 		}
//
// 		var docid = strings.ToLower(strings.TrimSpace(doc.Ref.ID))
// 		fmt.Printf("[FindDeadline] document id normalized value [%s], doc.IP value [%s]\n", docid, pks.IdentityProvider)
//
// 		if docid == ip {
//
// 			err = doc.DataTo(&pks)
// 			if err != nil {
// 				return 0, fmt.Errorf("error %#v, while convert DataTo pks object for %s", err, doc.Ref.ID)
// 			}
//
// 			// var kj = pks.KeyJournal
// 			// if kj == nil {
// 			// 	return 0, errors.New("key journal not found")
// 			// }
// 			// for k, v := range kj {
// 			// 	if k == kid {
// 			// 		dl = int64(v.(int64))
// 			// 		break
// 			// 	}
// 			// }
//
// 			break
// 		}
//
// 		pks = core.PublicKeySet{}
// 	}
//
// 	return dl, nil
// }

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
