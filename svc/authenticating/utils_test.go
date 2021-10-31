package authenticating

import (
	b64 "encoding/base64"
	"testing"
)

// Testing `getXClient` function to extract the client_id and client_secret values
func TestGetXClient(t *testing.T) {
	xic := "Basic " + b64.URLEncoding.EncodeToString([]byte("clientID:clientSECRET"))

	cid, csc := getXClient(xic)

	if cid != "clientID" || csc != "clientSECRET" {
		t.Fail()
	}
}
