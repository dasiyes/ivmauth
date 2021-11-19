package core

import "crypto/rsa"

// KeyJournal is repository of generated asymetric key pairs
// and all there attributes
type KeyJournal struct {
	Records []KeyRecord
}

// KeyRecord holds the key pairs and all their attributes.
type KeyRecord struct {
	Kid        string         `firestore:"kid"`
	Deadline   int64          `firestore:"deadline"`
	PublicKey  rsa.PublicKey  `firestore:"public_key"`
	PrivateKey rsa.PrivateKey `firestore:"private_key"`
}

// kj := map[string]interface{}{"n.a.": time.Now().Unix()}
type KJR interface {
	// AddKey will add a new key with its attributes in the repo
	AddKey(k *KeyRecord) error

	// FindDeadline is browse the repo for a given key id and return its deadline (expire date)
	FindDeadline(kid string) (dl int64, err error)
}
