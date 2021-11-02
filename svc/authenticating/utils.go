package authenticating

import (
	"bytes"
	"crypto/rsa"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
	"github.com/dasiyes/ivmconfig/src/pkg/config"
	"github.com/dgrijalva/jwt-go"
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

	// if r.TLS == nil {
	// 	return "", "", core.ErrTLS
	// }

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

// validateIDToken will provide validation of OpenIDConnect ID Tokens
func validateIDToken(rawIDToken string, idP string, pks pksrefreshing.Service) (*jwt.Token, *core.IDToken, error) {

	var err error
	var tkn *jwt.Token
	var oidt = core.IDToken{}

	_, err = pks.GetPKSCache(idP)
	if err != nil {
		return nil, nil, err
	}

	// validate idToken
	tkn, err = jwt.ParseWithClaims(rawIDToken, &oidt, func(token *jwt.Token) (interface{}, error) {

		tKid := token.Header["kid"].(string)
		alg := token.Method.Alg()
		if strings.ToUpper(token.Header["typ"].(string)) != "JWT" {
			return "", core.ErrAuthenticating
		}
		switch alg {
		case "RS256":
			n, e, err := pks.GetRSAPublicKey(idP, tKid)
			if err != nil {
				return nil, err
			}

			return &rsa.PublicKey{
				N: n,
				E: e,
			}, nil
		default:
			return "", nil
		}
	})

	if err != nil {
		return nil, nil, err
	}

	return tkn, &oidt, nil
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

// A server MUST respond with a 400 (Bad Request) status code to any
//  [x] HTTP/1.1 request message that lacks a Host header field
//  and
//  [x] to any request message that contains more than one Host header field
//	or
//  [x] a Host header field with an invalid field-value .
func checkValidClientAuthRequest(r *http.Request, cfg config.IvmCfg) (bool, error) {

	// The host is the address where the request is sent to.
	var host string = r.Host

	// The host header SHOULD be only one value. If there is more - bad request is returned.
	var hosts = r.Header.Values("Host")
	if len(hosts) > 1 {
		return false, core.ErrBadRequest
	}

	// The origin is the address where the request is sent from. Since the CORS is allowed, this value should be controlling the originates from where the library accepts calls from. [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin]
	var origin string = r.Header.Get("Origin")

	// The refrerrer value, as a difference from the origin, will include the full path from where the request was sent from. [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer]
	var referer = r.Referer()

	// [x] [host]: The address where the request was sent to. Should be domain where this library is authoritative to - i.e. ivmanto.dev
	var expected_host = cfg.GetAuthSvcURL()

	if host != expected_host || host == "" || expected_host == "" {
		return false, core.ErrBadRequest
	}

	var env string = cfg.GetEnv()
	if origin == "" && env == "prod" {
		//TODO [dev]: implement db support for taking the array of allowed origins
		fmt.Printf("BadRequest: missing origin value\n")
		return false, core.ErrBadRequest
	}

	if referer == "" {
		//TODO [design]: consider if this value must be part of the client Authentication process...
		fmt.Printf("INFO: missing referer value\n")
	}

	if r.Method != http.MethodPost {
		return false, fmt.Errorf("request method %s is not accepted. Only POST method is a valid request method", r.Method)
	}

	return true, nil
}

// getAndAuthRegisteredClient - will find the client from the request by its clientID and will authenticate it based on its type and respective credentials. In case of successful authentication will return the client object, otherwise error
func getAndAuthRegisteredClient(clients core.ClientRepository, cID, cSec string) (*core.Client, error) {

	// [ ] remove after debug
	fmt.Printf("provided clientID to authenticate: %s\n", cID)

	rc, err := clients.Find(core.ClientID(cID))
	if err != nil {
		return nil, fmt.Errorf("while finding clientID: %v in the database error raised: %#v", cID, err)
	}

	switch rc.ClientType {
	case core.Confidential:
		if cSec != "" && rc.ClientSecret == cSec {
			return rc, nil
		} else {
			return nil, fmt.Errorf("authentication failed for clientID %s, clientType %s, %#v", cID, rc.ClientType.String(), core.ErrClientAuth)
		}
	case core.Credentialed:
		// TODO [dev]: identify the use case for this client Type and implement the logic
		return nil, fmt.Errorf("unsupported client type. %#v", core.ErrBadRequest)
	case core.Public:
		// TODO [dev]: DO NOT trust the client identity. INVOLVE the resource owner in another comm channel?
		if cSec == "" && rc.ClientSecret == "" {
			return rc, nil
		}
		return nil, fmt.Errorf("unsupported client type. %#v", core.ErrBadRequest)
	default:
		return nil, fmt.Errorf("unsupported client type. %#v", core.ErrBadRequest)
	}
}
