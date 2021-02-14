package authenticating

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
	"ivmanto.dev/ivmauth/utils"
)

// Service is the interface that provides auth methods.
type Service interface {
	// RegisterNewRequest registring a new http request for authentication
	RegisterNewRequest(rh http.Header, body ivmanto.AuthRequestBody) (ivmanto.SessionID, error)

	// Validate the auth request attributes
	Validate(rh http.Header, body *ivmanto.AuthRequestBody, pks pksrefreshing.Service) (ivmanto.AccessToken, error)

	// AuthenticateClient authenticates the client sending the request for authenitcation of the resource owner.
	// request Header Authorization: Basic XXX
	AuthenticateClient(r *http.Request) error

	// GetRequestBody considers the contet type header and reads the request body within ivmanto.AuthRequestBody
	GetRequestBody(r *http.Request) (b *ivmanto.AuthRequestBody, err error)
}

type service struct {
	requests ivmanto.RequestRepository
	clients  ivmanto.ClientRepository
}

func (s *service) RegisterNewRequest(rh http.Header, body ivmanto.AuthRequestBody) (ivmanto.SessionID, error) {

	if len(rh) == 0 || utils.GetSize(body) == 0 {
		return "", ErrInvalidArgument
	}

	id := ivmanto.NextSessionID()
	ar := ivmanto.NewAuthRequest(id, rh, body)

	if err := s.requests.Store(ar); err != nil {
		return "", err
	}
	return ar.SessionID, nil
}

// Roles [RFC6749]
// OAuth defines four roles:
//    resource owner
//       An entity capable of granting access to a protected resource.
//       When the resource owner is a person, it is referred to as an
//       end-user.
//    resource server
//       The server hosting the protected resources, capable of accepting
//       and responding to protected resource requests using access tokens.
//    client
//       An application making protected resource requests on behalf of the
//       resource owner and with its authorization.  The term "client" does
//       not imply any particular implementation characteristics (e.g.,
//       whether the application executes on a server, a desktop, or other
//       devices).
//    authorization server [this service role in the domains Ivmanto]
//       The server issuing access tokens to the client after successfully
//       authenticating the resource owner and obtaining authorization.
//
// 	The interaction between the authorization server and resource server
// 	is beyond the scope of this specification.  The authorization server
// 	may be the same server as the resource server or a separate entity.
// 	A single authorization server may issue access tokens accepted by
// 	multiple resource servers.

// Validate receives all POST request calls to /auth path and validates
// them according to OAuth2 [RFC6749]
func (s *service) Validate(rh http.Header, body *ivmanto.AuthRequestBody, pks pksrefreshing.Service) (ivmanto.AccessToken, error) {
	// According to [RFC6479] Protocol Flow - this part is steps (C)-(D):
	// receives --(C)-- Authorization Grant -->
	// returns  <-(D)----- Access Token -------
	// (C)  The client requests an access token by authenticating with the
	//       authorization server and presenting the authorization grant.
	// (D)  The authorization server authenticates the client and validates
	//       the authorization grant, and if valid, issues an access token.

	// 1) Get the ClientID / ClientSecret from the req headers. [step (C) client authentication]
	// 1.1) authenticate the client [step (D) autenticate client]
	// step 1.1) is done by the method AuthenticateClient, called from authHandler.authenticateRequest

	// TODO: 2) Identify the grant_type [step (C) presents authorization grant]
	// The client receives an authorization grant, which is a
	// credential representing the resource owner’s authorization,
	// expressed using one of four grant types defined in this
	// specification or using an extension grant type.  The
	// authorization grant type depends on the method used by the
	// client to request authorization and the types supported by the
	// authorization server.
	// ...
	//1.3.  Authorization Grant
	// An authorization grant is a credential representing the resource
	// owner’s authorization (to access its protected resources) used by the
	// client to obtain an access token.  This specification defines four
	// grant types -- authorization code, implicit, resource owner password
	// credentials, and client credentials -- as well as an extensibility
	// mechanism for defining additional types.

	// Check grant type and identity provider name presence
	if rh.Get("x-grant-type") == "" || rh.Get("x-token-type") == "" {
		return ivmanto.AccessToken{}, ivmanto.ErrUnknownGrantType
	}

	var authGrantType, xgt, idP string
	var oidtoken *ivmanto.IDToken

	idP = rh.Get("x-token-type")
	xgt = rh.Get("x-grant-type")

	switch xgt {
	case "id_token":

		var err error
		var tkn *jwt.Token

		tkn, oidtoken, err = validateIDToken(body.IDToken, idP, pks)

		if err != nil || !tkn.Valid {
			return ivmanto.AccessToken{}, ErrAuthenticating
		}

		err = validateOpenIDClaims(oidtoken, body, idP)
		if err != nil {
			return ivmanto.AccessToken{}, ErrAuthenticating
		}

		authGrantType = "implicit"

	case "password":
		authGrantType = "password_credentials"
	case "code":
		authGrantType = "authorization_code"
	default:
		authGrantType = "client_credentials"
	}

	switch authGrantType {

	// 1.3.1.  Authorization Code
	// 	The authorization code is obtained by using an authorization server
	// 	as an intermediary between the client and resource owner.  Instead of
	// 	requesting authorization directly from the resource owner, the client
	// 	directs the resource owner to an authorization server (via its
	// 	user-agent as defined in [RFC2616]), which in turn directs the
	// 	resource owner back to the client with the authorization code.
	// 	Before directing the resource owner back to the client with the
	// 	authorization code, the authorization server authenticates the
	// 	resource owner and obtains authorization.  Because the resource owner
	// 	only authenticates with the authorization server, the resource
	// 	owner’s credentials are never shared with the client.
	// 	The authorization code provides a few important security benefits,
	// 	such as the ability to authenticate the client, as well as the
	// 	transmission of the access token directly to the client without
	// 	passing it through the resource owner’s user-agent and potentially
	// 	exposing it to others, including the resource owner.
	case "authorization_code":

	case "implicit":

		fmt.Printf("...evrything looks good: %#v;\n", oidtoken)
		// TODO: to issue the Access Token?
		// TODO: in separate go routine register the user from the IDToken, if not already in the db. if the user email is already in - connect the Identity Provider to the existing account.

	case "password_credentials":

	case "client_credentials":

	default:

	}
	// TODO: 2.1) switch according to the authorization GRANT TYPE
	// ...
	// TODO: 2.2) validate the authorization grant
	// ...
	// TODO: 3) ONLY IF 2.2 is VALID - compose the correct access token object!
	// ...
	at := ivmanto.AccessToken{}
	return at, nil
}

// 3.2.1.  Client Authentication
// 	Confidential clients or other clients issued client credentials MUST
// 	authenticate with the authorization server as described in
// 	Section 2.3 when making requests to the token endpoint.  Client
// 	authentication is used for:
// 	o  Enforcing the binding of refresh tokens and authorization codes to
// 		the client they were issued to.  Client authentication is critical
// 		when an authorization code is transmitted to the redirection
// 		endpoint over an insecure channel or when the redirection URI has
// 		not been registered in full.
// 	o  Recovering from a compromised client by disabling the client or
// 		changing its credentials, thus preventing an attacker from abusing
// 		stolen refresh tokens.  Changing a single set of client
// 		credentials is significantly faster than revoking an entire set of
// 		refresh tokens.
// 	o  Implementing authentication management best practices, which
// 		require periodic credential rotation.  Rotation of an entire set
// 		of refresh tokens can be challenging, while rotation of a single
// 		set of client credentials is significantly easier.
// 	A client MAY use the "client_id" request parameter to identify itself
// 	when sending requests to the token endpoint.  In the
// 	"authorization_code" "grant_type" request to the token endpoint, an
// 	unauthenticated client MUST send its "client_id" to prevent itself
// 	from inadvertently accepting a code intended for a client with a
// 	different "client_id".  This protects the client from substitution of
// 	the authentication code.  (It provides no additional security for the
// 	protected resource.)

// AuthenticateClient authenticates the client sending the request for authenitcation of the resource owner.
func (s *service) AuthenticateClient(r *http.Request) error {

	var cID, cSec string
	var err error

	ahct := r.Header.Get("Content-Type")
	switch ahct {
	case "application/x-www-form-urlencoded":
		cID, cSec, err = getClientIDSecWFUE(r)
		if err != nil {
			return ErrClientAuth
		}
	case "application/json":
		cID, cSec, _ = r.BasicAuth()
		if cID == "" || cSec == "" {
			return ErrClientAuth
		}
	default:
		return ErrClientAuth
	}

	// Find the client registration
	rc, err := s.clients.Find(ivmanto.ClientID(cID))
	if err != nil {
		return err
	}
	if rc.ClientSecret != cSec {
		return ErrClientAuth
	}
	return nil
}

// GetRequestBody considers the contet type header and reads the request body within ivmanto.AuthRequestBody
func (s *service) GetRequestBody(r *http.Request) (*ivmanto.AuthRequestBody, error) {

	var err error
	var rb ivmanto.AuthRequestBody

	if r.Header.Get("Content-Type") == "application/json" {

		if err = json.NewDecoder(r.Body).Decode(&rb); err != nil {
			return nil, ErrGetRequestBody
		}

	} else if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {

		var body []byte
		var fp []string
		var lblval []string

		// TODO: ENABLE after debug completed
		// if r.TLS == nil {
		// 	return "", errTLS
		// }

		defer r.Body.Close()
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, ErrGetRequestBody
		}

		fp = strings.Split(string(body), "&")
		for _, p := range fp {

			lblval = strings.Split(p, "=")

			switch lblval[0] {
			case "idtoken":
				rb.IDToken = lblval[1]
			case "nonce":
				rb.Nonce = lblval[1]
			case "asrCID":
				rb.AsrCID = lblval[1]
			}
		}
	}
	return &rb, nil
}

// Get the client ID and the Client secret from web form url encoded
func getClientIDSecWFUE(r *http.Request) (cID string, cSec string, err error) {

	// standard: https://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1
	// Forms submitted with this content type must be encoded as follows:
	//
	// Control names and values are escaped. Space characters are replaced by `+', and then reserved characters are escaped as described in [RFC1738], section 2.2: Non-alphanumeric characters are replaced by `%HH', a percent sign and two hexadecimal digits representing the ASCII code of the character. Line breaks are represented as "CR LF" pairs (i.e., `%0D%0A').
	// The control names/values are listed in the order they appear in the document. The name is separated from the value by `=' and name/value pairs are separated from each other by `&'.

	// TODO: remove after debug
	// if r.TLS == nil {
	// 	return "", "", ErrTLS
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

	// set the body back to the request. For cases when needs to read again.
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	return cID, cSec, nil
}

// validateIDToken will provide validation of OpenIDConnect ID Tokens
func validateIDToken(rawIDToken string, idP string, pks pksrefreshing.Service) (*jwt.Token, *ivmanto.IDToken, error) {

	var err error
	var tkn *jwt.Token
	var oidt = ivmanto.IDToken{}

	_, err = pks.GetPKSCache(idP)
	if err != nil {
		return nil, nil, err
	}

	// validate idToken
	tkn, err = jwt.ParseWithClaims(rawIDToken, &oidt, func(token *jwt.Token) (interface{}, error) {

		tKid := token.Header["kid"].(string)
		alg := token.Method.Alg()
		if strings.ToUpper(token.Header["typ"].(string)) != "JWT" {
			return "", ErrAuthenticating
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

// validateOpenIDClaims will validate the jwtoken's claims from the respective Identity Provider as IDToken
// and return the IDToken in successful validation
func validateOpenIDClaims(oidt *ivmanto.IDToken, body *ivmanto.AuthRequestBody, idP string) error {

	// verify the client side sent nonce and asrCID to match the values in the token's claims
	if oidt.Nonce != body.Nonce {
		return ErrSessionToken
	}

	// Uncomment beow code if changing IDToken Aud from string to []string
	//
	// var matchAud bool = false
	// for _, ai := range oidt.Aud {
	// 	if ai == body.AsrCID {
	// 		matchAud = true
	// 		break
	// 	}
	// }
	// if !matchAud {
	// 	return ErrCompromisedAud
	// }

	if oidt.Azp != body.AsrCID {
		return ErrCompromisedAud
	}

	// TODO: 1) Validate the issuer to match the expected Identity Provider

	// validate if the IDToken pass the standard requirements of OpenID Connect for IDToken
	if err := oidt.Valid(); err != nil {
		return ErrInvalidIDToken
	}

	// TODO: implement token's claims validation logic
	return nil
}

// NewService creates a authenticating service with necessary dependencies.
func NewService(requests ivmanto.RequestRepository, clients ivmanto.ClientRepository) Service {
	return &service{
		requests: requests,
		clients:  clients,
	}
}

// ErrInvalidArgument is returned when one or more arguments are invalid.
var ErrInvalidArgument = errors.New("invalid argument")

// ErrClientAuth is returned when client Basic authentication fails
var ErrClientAuth = errors.New("invalid client authentication credentials")

// ErrGetRequestBody is returned when reading the request body
var ErrGetRequestBody = errors.New("error reading request body")

// ErrAuthenticating is returned when the authentication process fails
var ErrAuthenticating = errors.New("authentication failed")

// ErrTLS - returned when the content-type is set to "application/x-www-form-urlencoded" and no TLS is used
var ErrTLS = errors.New("unsecured transport of credentials")

// ErrSessionToken - when the NONCE value from the IDToken does not match the value sent from the client in the auth request body
var ErrSessionToken = errors.New("invalid session token")

// ErrCompromisedAud - will be returned when the valid of the ClientID returned to the client from the authorization server alongside with the IDToken, does not match the aud value in the IDToken
var ErrCompromisedAud = errors.New("compromised audience")

// ErrInvalidIDToken - will be returned if the IDToken does not match the requirements of the OPenID standard for IDToken
var ErrInvalidIDToken = errors.New("invalid openID IDToken")
