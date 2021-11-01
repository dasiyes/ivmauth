package authenticating

import (
	"crypto/tls"
	b64 "encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// Testing `getClientIDSecWFUE` function to extract the client_id and client_secret values from the request body as form url-encoded values
func TestGetClientIDSecWFUE(t *testing.T) {

	// [!] step-1 prepare mock request
	// ===============================
	body := strings.NewReader("client_id=clientID&some_attribute=someVal&client_secret=clientSECRET")
	schema := "http://"
	th := "192.0.2.1:1234"
	target := fmt.Sprintf("%s%s", schema, th)

	// 192.0.2.0/24 is "TEST-NET" in RFC 5737 for use solely in
	// documentation and example source code and should not be
	// used publicly.
	r := httptest.NewRequest(http.MethodPost, target, body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "example.com"
	// =================================

	t.Run("Test error TLS",
		func(t *testing.T) {
			cid, csc, err := getClientIDSecWFUE(r)

			if cid != "" && csc != "" && err.Error() != "unsecured transport of credentials" {
				t.Logf("cid: %s, csc: %s, error: %#v", cid, csc, err)
				t.Fail()
			}
		})

	// Config TLS to to make it work
	r = httptest.NewRequest(http.MethodPost, "https://192.0.2.1:1234", nil)
	r.TLS = &tls.ConnectionState{
		Version:           tls.VersionTLS12,
		HandshakeComplete: true,
		ServerName:        r.Host,
	}

	t.Run("Test error nil body",
		func(t *testing.T) {
			cid, csc, err := getClientIDSecWFUE(r)

			if cid != "" && csc != "" && err != nil {
				t.Logf("cid: %s, csc: %s, error: %#v", cid, csc, err)
				t.Fail()
			}
		})

	r = httptest.NewRequest(http.MethodPost, "https://192.0.2.1:1234", body)

	t.Run("Test positive result",
		func(t *testing.T) {
			cid, csc, err := getClientIDSecWFUE(r)

			if cid != "clientID" || csc != "clientSECRET" || err != nil {
				t.Logf("cid: %s, csc: %s, error: %v", cid, csc, err)
				t.Fail()
			}
		})
}
