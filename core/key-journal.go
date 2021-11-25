package core

// KeyJournal is repository of generated asymetric key pairs
// and all there attributes
type KeyJournal struct {
	Records []KeyRecord
}

// KeyRecord holds the key pairs and all their attributes.
type KeyRecord struct {
	Kid        string `firestore:"kid"`
	Deadline   int64  `firestore:"deadline"`
	PublicKeyN string `firestore:"public_key_n"`
	PublicKeyE string `firestore:"public_key_e"`
}

// kj := map[string]interface{}{"n.a.": time.Now().Unix()}
type KJR interface {
	// AddKey will add a new key with its attributes in the repo
	AddKey(k *KeyRecord) error

	// FindDeadline is browse the repo for a given key id and return its deadline (expire date)
	FindDeadline(kid string) (dl int64, err error)
}
