package authenticating

import (
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
)

// getXClient - retrievs the ClientID and Client Secret from the provided xic string that represents the ClientID and ClientSecret as Basic auth string.
func getXClient(xic string) (cid string, csc string) {

	// TODO: remove after debug
	fmt.Printf("xic: %v\n", xic)

	cis := strings.Split(xic, " ")
	if len(cis) != 2 || cis[0] != "Basic" {
		return "", ""
	}

	//dc, err := base64url.Decode(cis[1])
	dc, err := b64.URLEncoding.DecodeString(cis[1])
	if err != nil {
		return "", ""
	}

	cp := strings.Split(string(dc), ":")
	if len(cp) == 1 {
		return "", ""
	}

	return cp[0], cp[1]
}

// getClientIDSecWFUE - retrievs the ClientID and the Client Secret from the request body and the content type application/x-www-form-urlencoded.
// standard: https://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1
// Forms submitted with this content type must be encoded as follows:
//
// Control names and values are escaped. Space characters are replaced by `+', and then reserved characters are escaped as described in [RFC1738], section 2.2: Non-alphanumeric characters are replaced by `%HH', a percent sign and two hexadecimal digits representing the ASCII code of the character. Line breaks are represented as "CR LF" pairs (i.e., `%0D%0A').
// The control names/values are listed in the order they appear in the document. The name is separated from the value by `=' and name/value pairs are separated from each other by `&'.
func getClientIDSecWFUE(r *http.Request) (cID, cSec string, err error) {

	if r.TLS == nil {
		return "", "", core.ErrTLS
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", "", err
	}

	fp := strings.Split(string(body), "&")
	for _, p := range fp {
		if strings.HasPrefix(p, "client_id") {
			cID = strings.Split(p, "=")[1]
		} else if strings.HasPrefix(p, "client_secret") {
			cSec = strings.Split(p, "=")[1]
		}
	}

	// set the body back to the request. For cases when needs to read it again.
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	return cID, cSec, nil
}

// validateOpenIDClaims - will validate the jwtoken's claims from the respective Identity Provider as IDToken
// and return nil error in successful validation.
//
// [ ] verify the client side set nonce and asrCID to match the values in the token's claims
// [ ] validate the IDToken against the openID Connect standard
// [ ] validate the issuer to match the expected Identity Provider
// [ ] verify the authorized party (Azp) to match clienID
func validateOpenIDClaims(
	oidt *core.IDToken,
	body *core.AuthRequestBody,
	idP string,
	pks pksrefreshing.Service) error {

	var err error

	if oidt.Nonce != body.Nonce {
		return core.ErrSessionToken
	}

	// ISSUE: jwt-go package does not support loading the token claims into IDToken when the AUD type is set to array of []string. With flat string type works well.
	// ? TODO: report the issue to package repo...

	if oidt.Aud != body.AsrCID {
		return core.ErrCompromisedAud
	}

	if err = oidt.Valid(); err != nil {
		return err
	}

	var issval string

	issval, err = pks.GetIssuerVal(idP)
	if err != nil {
		return fmt.Errorf("%v inner %v", core.ErrInvalidIDToken, err)
	}
	if oidt.Iss != issval {
		return core.ErrInvalidIDToken
	}

	if oidt.Azp != "" && body.ClientID != "" {
		if oidt.Azp != body.ClientID {
			return fmt.Errorf("%v inner %v", core.ErrInvalidIDToken, "authorized party not verified")
		}
	}

	if oidt.Aud != body.ClientID {
		return core.ErrInvalidIDToken
	}

	// TODO: Check if this key is available in the OpenID spec for other Identity Providers
	if !oidt.EmailVerified {
		return core.ErrInvalidIDToken
	}

	return nil
}
