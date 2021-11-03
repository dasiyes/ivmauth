// Roles [RFC6749]
// OAuth defines four roles:
// [!]	**resource owner [RO]**
//       	An entity capable of granting access to a protected resource.
//       	When the resource owner is a person, it is referred to as an
//       	end-user.
// [!]	**resource server [RS]**
//       	The server hosting the protected resources, capable of accepting
//       	and responding to protected resource requests using access tokens.
// [!] 	**client [C]**
//       	An application making protected resource requests on behalf of the
//       	resource owner and with its authorization.  The term "client" does
//       	not imply any particular implementation characteristics (e.g.,
//       	whether the application executes on a server, a desktop, or other
//       	devices).
// [!]	**authorization server [AS]**
//				[this service role in the domains Ivmanto]
//       	The server issuing access tokens to the client after successfully
//       	authenticating the resource owner and obtaining authorization.
//
// 	The interaction between the authorization server and resource server
// 	is beyond the scope of this specification.  The authorization server
// 	may be the same server as the resource server or a separate entity.
// 	A single authorization server may issue access tokens accepted by
// 	multiple resource servers.

// 1.3.  Authorization Grant 	[RFC6749]
//  An authorization grant is a credential representing the resource owner’s authorization (to access its protected resources) used by the client to obtain an access token.  This specification defines four grant types -- authorization code, implicit, resource owner password credentials, and client credentials -- as well as an extensibility mechanism for defining additional types.

// 1.3.1.  Authorization Code
// 	The authorization code is obtained by using an authorization server as an intermediary between the client and resource owner.  Instead of requesting authorization directly from the resource owner, the client directs the resource owner to an authorization server (via its user-agent as defined in [RFC2616]), which in turn directs the resource owner back to the client with the authorization code. Before directing the resource owner back to the client with the authorization code, the authorization server authenticates the resource owner and obtains authorization.  Because the resource owner only authenticates with the authorization server, the resource owner’s credentials are never shared with the client. The authorization code provides a few important security benefits, such as the ability to authenticate the client, as well as the transmission of the access token directly to the client without passing it through the resource owner’s user-agent and potentially exposing it to others, including the resource owner.

// 3.2.1.  Client Authentication
//	Confidential clients or other clients issued client credentials MUST authenticate with the authorization server as described in Section 2.3 when making requests to the token endpoint.  Client authentication is used for:
//	o  Enforcing the binding of refresh tokens and authorization codes to the client they were issued to.  Client authentication is critical when an authorization code is transmitted to the redirection endpoint over an insecure channel or when the redirection URI has not been registered in full.
//	o  Recovering from a compromised client by disabling the client or changing its credentials, thus preventing an attacker from abusing stolen refresh tokens.  Changing a single set of client credentials is significantly faster than revoking an entire set of refresh tokens.
//	o  Implementing authentication management best practices, which require periodic credential rotation.  Rotation of an entire set of refresh tokens can be challenging, while rotation of a single set of client credentials is significantly easier. A client MAY use the "client_id" request parameter to identify itself when sending requests to the token endpoint.  In the "authorization_code" "grant_type" request to the token endpoint, an unauthenticated client MUST send its "client_id" to prevent itself from inadvertently accepting a code intended for a client with a different "client_id".  This protects the client from substitution of the authentication code.  (It provides no additional security for the protected resource.)

// Validate receives all POST request calls to /auth path and validates
// them according to OAuth2 [RFC6749]
//
// According to [RFC6479] Protocol Flow - this part is steps (C)-(D):
// receives --(C)-- Authorization Grant -->
// returns  <-(D)----- Access Token -------
// (C)  The client requests an access token by authenticating with the
//       authorization server and presenting the authorization grant.
// (D)  The authorization server authenticates the client and validates
//       the authorization grant, and if valid, issues an access token.
//
// * [1] Get the ClientID / ClientSecret from the req headers. [step (C) client authentication]
// * [1.1] authenticate the client [step (D) autenticate client]
// 	 - step 1.1) is done by the method AuthenticateClient, called from authHandler.authenticateRequest
//
// * [2] Identify the grant_type [step (C) presents authorization grant] The client receives an authorization grant, which is a credential representing the resource owner’s authorization, expressed using one of four grant types defined in this specification or using an extension grant type.  The authorization grant type depends on the method used by the client to request authorization and the types supported by the authorization server.
// * [2.1] Switch the logic based on the identified grant_type at [2].
// * [2.2] validate the authorization grant
// * [3] issue a new Access Token for the realm core. Consider the scopes.

package authenticating

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/dataservice/firestoredb"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
	"github.com/dasiyes/ivmconfig/src/pkg/config"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

// TODO [dev]: replace the following two packages:
// "github.com/golang-jwt/jwt" replace with "github.com/golang-jwt/jwt"
// [x] "github.com/dvsekhvalnov/jose2go/base64url"

// TODO: Review the service concept against the checklist below:
// **Authentication Framework Evaluation Checklist**
// [x] Provides the ability to exchange credentials (username/password, token, and so on) for a valid session.
// [ ] Supports proper session management (www.owasp.org/index.php/Session_Management_Cheat_Sheet).
// [ ] Lets users opt in to two-factor authentication.
// [x] In a browser-based environment, properly marks the session cookie as HTTPOnly (www.owasp.org/index.php/HttpOnly) and secure (www.owasp.org/index.php/SecureFlag).
// [ ] Provides support for Cross-Site Request Forgery (CSRF; goo.gl/TwcSJX) protection/ defenses.
// [x] Supports token-based authentication mechanisms (such as OAuth2).
// [x] Supports proper password storage (www.owasp.org/index.php/Password_Storage_Cheat_Sheet).
//		 - bcrypt with cost (work factor) 12 is used
// [ ] Provides integration with third-party authentication providers.
// [ ] Logs all authentication activity (and supports proper audit trails  of login/ logout, token  creation  and exchange, revocation,  and so on).
// [ ] Has a public record of good security response, disclosure, and fixes.
// [ ] Supports secure account-recovery flows (third-party authentication providers make this easier).
// [ ] Never exposes credentials in plaintext, whether in user interfaces, URLs, storage, logs, or network communications.
// [ ] Enforces use of credentials with sufficient entropy.
// [ ] Protects against online brute-force attacks.
// [ ] Protects against session fixation attacks.

// Service is the interface that provides auth methods.
type Service interface {

	// DEPRICATED Validate the auth request according to OAuth2 sepcification (see the notes at the top of of this file)
	Validate(rh *http.Header, body *core.AuthRequestBody, pks pksrefreshing.Service, client *core.Client) (*core.AccessToken, error)

	// AuthenticateClient authenticates the client sending the request for authenitcation of the resource owner.
	// request Header Authorization: Basic XXX
	AuthenticateClient(r *http.Request) (*core.Client, error)

	// GetRequestBody considers the contet type header and reads the request body within core.AuthRequestBody
	GetRequestBody(r *http.Request) (b *core.AuthRequestBody, err error)

	// IssueAccessToken for the successfully authenticated and authorized requests [realm IVMANTO]
	IssueAccessToken(oidt *core.IDToken, client *core.Client) (*core.AccessToken, error)

	// CheckUserRegistration search for the user from oidtoken in the db. Id not found a new one will be registered.
	CheckUserRegistration(oidtoken *core.IDToken)

	// RegisterUser will create a new user in the ivmauth db
	RegisterUser(names, email, password string) (*core.User, error)

	// UpdateUser will update the user object from the parameter in the db
	UpdateUser(u *core.User) error

	// ValidateUsersCredentials will use the UsersRepository to find and validate user's credentials
	ValidateUsersCredentials(email, pass string) (bool, error)

	// GetClientsRedirectURI will return the registred redirection URI for a specific clientID
	GetClientsRedirectURI(cid string) ([]string, error)

	// IssueIvmIDToken issues IDToken for users registered on Ivmanto's OAuth server
	IssueIvmIDToken(uid core.UserID, cid core.ClientID) *core.IDToken
}

type service struct {
	requests core.RequestRepository
	clients  core.ClientRepository
	users    core.UserRepository
	config   config.IvmCfg
}

// DEPRICATED this method will be replaced by several new methods to handle apiGateway with Session Manager application architecture
func (s *service) Validate(
	rh *http.Header,
	body *core.AuthRequestBody,
	pks pksrefreshing.Service,
	client *core.Client) (*core.AccessToken, error) {

	var err error

	var authGrantType, xgt, idP string
	var oidtoken *core.IDToken
	var usr *core.User

	idP = rh.Get("x-token-type")
	xgt = rh.Get("x-grant-type")

	// [2]
	if xgt == "" {
		return nil, core.ErrUnknownGrantType
	} else if xgt == "id_token" && idP == "" {
		return nil, core.ErrBadRequest
	}

	// [2.1]
	switch xgt {
	case "id_token":

		var tkn *jwt.Token

		tkn, oidtoken, err = validateIDToken(body.IDToken, idP, pks)

		if err != nil || !tkn.Valid {
			return nil, core.ErrAuthenticating
		}

		err = validateOpenIDClaims(oidtoken, body, idP, pks)
		if err != nil {
			return nil, core.ErrAuthenticating
		}

		authGrantType = "implicit"

	case "password":

		authGrantType = "password_credentials"

		// TODO: [IVM-6] implement password flow
		usr, err = s.users.Find(core.UserID(body.Email))
		if err != nil {
			return nil, err
		}

		err = bcrypt.CompareHashAndPassword([]byte(usr.Password), []byte(body.Password))
		if err != nil {
			return nil, core.ErrAuthenticating
		}
		usr.Password = []byte{}

	case "code":
		authGrantType = "authorization_code"
	default:
		authGrantType = "client_credentials"
	}

	// [2.2]
	var at *core.AccessToken

	switch authGrantType {

	case "authorization_code":

	case "implicit":

		go s.CheckUserRegistration(oidtoken)

		at, err = s.IssueAccessToken(oidtoken, client)
		if err != nil {
			return nil, core.ErrIssuingAT
		}

	case "password_credentials":

		oidt := core.IDToken{Email: string(usr.UserID), Sub: string(usr.SubCode)}
		at, err = s.IssueAccessToken(&oidt, client)
		if err != nil {
			return nil, core.ErrIssuingAT
		}

	case "client_credentials":

	default:

	}

	return at, nil
}

// ValidateUsersCredentials will use the UsersRepository to find and validate user's credentials
func (s *service) ValidateUsersCredentials(email, pass string) (bool, error) {
	var valid = false

	usr, err := s.users.Find(core.UserID(email))
	if err != nil {
		return valid, fmt.Errorf("error finding user %s: %#v", email, err.Error())
	}

	err = bcrypt.CompareHashAndPassword(usr.Password, []byte(pass))
	if err != nil {
		return valid, fmt.Errorf("usr.Password=%v; length: %d; pass=%s; error:%s", usr.Password, len(usr.Password), pass, err.Error())
	}
	if err == nil {
		valid = true
	}

	return valid, nil
}

// [DOC]
// 3.2.1.  Client Authentication [The OAuth 2.1 Authorization Framework] DRAFT
//
//    Confidential clients or other clients issued client credentials MUST
//    authenticate with the authorization server as described in
//    Section 2.3 when making requests to the token endpoint.  Client
//    authentication is used for:
//
//    *  Enforcing the binding of refresh tokens and authorization codes to
//       the client they were issued to.  Client authentication is critical
//       when an authorization code is transmitted to the redirection
//       endpoint over an insecure channel or when the redirection URI has
//       not been registered in full.
//
//    *  Recovering from a compromised client by disabling the client or
//       changing its credentials, thus preventing an attacker from abusing
//			 stolen refresh tokens.  Changing a single set of client
//       credentials is significantly faster than revoking an entire set of
//       refresh tokens.
//
//    *  Implementing authentication management best practices, which
//       require periodic credential rotation.  Rotation of an entire set
//       of refresh tokens can be challenging, while rotation of a single
//       set of client credentials is significantly easier.
//
//    A client MAY use the "client_id" request parameter to identify itself
//    when sending requests to the token endpoint.  In the
//    "authorization_code" "grant_type" request to the token endpoint, an
//    unauthenticated client MUST send its "client_id" to prevent itself
//    from inadvertently accepting a code intended for a client with a
//    different "client_id".  This protects the client from substitution of
//    the authentication code.  (It provides no additional security for the
//    protected resource.)

// [DOC]
// 2.3.  Client Authentication [The OAuth 2.1 Authorization Framework] DRAFT
//
//    If the client type is confidential, the client and authorization
//    server establish a client authentication method suitable for the
//    security requirements of the authorization server.  The authorization
//    server MAY accept any form of client authentication meeting its
//    security requirements.
//
//    Confidential clients are typically issued (or establish) a set of
//    client credentials used for authenticating with the authorization
//    server (e.g., password, public/private key pair).
//
//    Authorization servers SHOULD use client authentication if possible.
//
//    [!] It is RECOMMENDED to use asymmetric (public-key based) methods for
//    client authentication such as mTLS [RFC8705] or "private_key_jwt"
//    [OpenID].  When asymmetric methods for client authentication are
//    used, authorization servers do not need to store sensitive symmetric
//    keys, making these methods more robust against a number of attacks.
//
//    The authorization server MAY establish a client authentication method
//    with public clients.  However, the authorization server MUST NOT rely
//    on public client authentication for the purpose of identifying the
//    client.
//
//    [!][x] The client MUST NOT use more than one authentication method in each
//    request.

// TODO: OpenID Connect guidences to follow (https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
func (s *service) AuthenticateClient(r *http.Request) (*core.Client, error) {

	var cID, cSec string
	var err error

	// Checking if the request qualifies as **VALID**
	ok, err := checkValidClientAuthRequest(r, s.config)
	if !ok && err != nil {
		return nil, fmt.Errorf("while validating client auth rquest, error: %#v!\n %#v", err, core.ErrBadRequest)
	}

	// [!] Validate only Client Exists.
	// This will ONLY validate that the clientID is registered in the
	// database => thus IS VALID.
	// Cases that are validated will NOT proceed with authentication.
	// isClientIDValidateCase validates the use-cases!
	if isClientIDValidateCase(r) {
		rc, err := validateClientExists(r, s.clients)
		if err != nil {
			return nil, fmt.Errorf("while validating client_id exists, error: %#v! %#v", err, core.ErrBadRequest)
		}
		return rc, nil
	}

	// [DOC]
	// This section defines a set of Client Authentication methods that are used by Clients
	// to authenticate to this Authorization Server when using the Token Endpoint. During
	// Client Registration, the RP (Client) MAY register a Client Authentication method. If // no method is registered, the default method is `client_secret_basic`.
	//
	//These Client Authentication methods supported by (Ivmanto's OAuth server) are:
	//
	// `client_secret_basic`:
	// Clients that have received a `client_secret` value from the Authorization Server
	// authenticate with the Authorization Server in accordance with Section 2.3.1 of
	// OAuth 2.0 [RFC6749] using the **HTTP Basic authentication scheme**.
	//
	// `client_secret_post`:
	// Clients that have received a `client_secret` value from the Authorization Server,
	// authenticate with the Authorization Server in accordance with Section 2.3.1 of
	// OAuth 2.0 [RFC6749] by including the **Client Credentials in the request body**.
	//
	// `none`:
	// The Client does not authenticate itself at the Token Endpoint, either because it
	// is a Public Client with no Client Secret or other authentication mechanism.

	// [!] AuthenticateClient method `client_secret_basic`
	//		 - Ivmanto OAuth server specific for Basic auth is that IF header Authrozation is taken for Bearer token, to use as alternative custome header `X-Ivm-Client`.
	var hav = r.Header.Get("Authorization")
	if !strings.HasPrefix(hav, "Basic ") {
		// Use the alternative custom header `X-Ivm-Client`
		hav = r.Header.Get("X-Ivm-Client")
	}

	// authenticate using hav
	if strings.HasPrefix(hav, "Basic ") {

		cID, cSec = getClientIDSecFromBasic(hav)
		if cID == "" {
			return nil, fmt.Errorf("client_secret_basic method failed: invalid clientID [%s] or client secret. %#v", cID, core.ErrBadRequest)
		}

		rc, err := getAndAuthRegisteredClient(s.clients, cID, cSec)
		if err != nil {
			return nil, fmt.Errorf("client_secret_basic method failed. Auth error %#v, %#v", err, core.ErrBadRequest)
		}

		// returns the registered client object as means of `it is found and authenticated`!
		return rc, nil
	}

	// client auth method `client_secret_basic` can not be used for this request due to missing Header value!
	// Continue checking for
	// [!] AuthenticateClient method `client_secret_post`
	var hct = r.Header.Get("Content-Type")
	if hct == "application/x-www-form-urlencoded" {
		cID, cSec, err = getClientIDSecWFUE(r)
		if err != nil {
			return nil, fmt.Errorf("client_secret_post method failed. Error %#v. %#v", err, core.ErrBadRequest)
		}

		rc, err := getAndAuthRegisteredClient(s.clients, cID, cSec)
		if err != nil {
			return nil, fmt.Errorf("client_secret_post method failed. Auth error %#v, %#v", err, core.ErrBadRequest)
		}

		// returns the registered client object as means of `it is found and authenticated`!
		return rc, nil
	}

	return nil, fmt.Errorf("client_secret_post method failed. Unsupported content type %s. %#v", hct, core.ErrBadRequest)
}

// GetRequestBody considers the contet type header and reads the request body within core.AuthRequestBody
func (s *service) GetRequestBody(r *http.Request) (*core.AuthRequestBody, error) {

	var err error
	var rb core.AuthRequestBody

	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {

		if err = json.NewDecoder(r.Body).Decode(&rb); err != nil {
			return nil, core.ErrGetRequestBody
		}

	} else if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {

		var body []byte
		var fp []string
		var lblval []string

		defer r.Body.Close()
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, core.ErrGetRequestBody
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
			case "client_id":
				rb.ClientID = lblval[1]
			case "name":
				rb.Name = lblval[1]
			case "email":
				rb.Email = lblval[1]
			case "password":
				rb.Password = lblval[1]
			}
		}
	}
	return &rb, nil
}

// IssueAccessToken for the successfully authenticated and authorized requests [realm IVMANTO]
func (s *service) IssueAccessToken(oidt *core.IDToken, client *core.Client) (*core.AccessToken, error) {

	atcfg := s.config.GetATC()
	scopes := client.Scopes

	iat := core.NewIvmantoAccessToken(&scopes, atcfg)
	return iat, nil
}

// Registration of new user on Ivmanto realm
func (s *service) RegisterUser(names, email, password string) (*core.User, error) {

	usr, err := s.users.Find(core.UserID(email))
	if err == nil && usr != nil {
		return nil, fmt.Errorf("user %#v already registered in the db", usr.UserID)
	}
	if err != nil && err != firestoredb.ErrUserNotFound {
		return nil, fmt.Errorf("failed to confirm that the user is NOT yet registered: %#v", err)
	}

	if names == "" || email == "" || password == "" {
		return nil, fmt.Errorf("one or more mandatory attribute(s) is empty! Names: %s, email: %s", names, email)
	}

	nUsr, errnu := core.NewUser(core.UserID(email))
	if errnu != nil {
		return nil, fmt.Errorf("error while creating new user object: %#v", errnu)
	}

	nUsr.Name = names

	nUsr.Status = core.EntryStatus(core.Draft)

	var nup, errgp = bcrypt.GenerateFromPassword([]byte(password), 12)
	if errgp != nil {
		return nil, fmt.Errorf("error while bcrypting the password: %#v", errgp)
	}

	// Compare new hash with the pass
	err = bcrypt.CompareHashAndPassword(nup, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("error when compare new hash with the pass")
	}

	nUsr.Password = nup

	if err = s.users.Store(nUsr); err != nil {
		return nil, fmt.Errorf("error saving new user: %#v", err)
	}

	fmt.Printf("user %#v successfully registred.\n", nUsr.UserID)
	return nUsr, nil
}

// UpdateUser will update the user changes in the DB
func (s *service) UpdateUser(u *core.User) error {
	if err := s.users.Store(u); err != nil {
		return err
	}
	return nil
}

// Checking the users if the user from openID token is registred or is new
func (s *service) CheckUserRegistration(oidtoken *core.IDToken) {

	usr, err := s.users.Find(core.UserID(oidtoken.Email))
	if err != nil {
		if err == firestoredb.ErrUserNotFound {
			nUsr, err := core.NewUser(core.UserID(oidtoken.Email))
			if err != nil {
				fmt.Printf("error while creating a new user: %#v;\n", err)
			}
			nUsr.Name = oidtoken.Name
			nUsr.Avatar = oidtoken.Picture
			nUsr.Status = core.EntryStatus(core.Draft)
			nUsr.OIDCProvider = oidtoken.Iss

			if err = s.users.Store(nUsr); err != nil {
				fmt.Printf("error saving new user: %#v;\n", err)
				return
			}
			fmt.Printf("user %#v successfully registred\n", nUsr.UserID)
			return
		}
		fmt.Printf("error while searching for a user: %#v;\n", err)
		return
	}
	if usr.OIDCProvider == "" {
		usr.OIDCProvider = oidtoken.Iss
		_ = s.users.Store(usr)
	}
	fmt.Printf("user %#v already registered in the db.", usr.UserID)
}

// GetClientsRedirectURI will return the registred redirection URI for a specific clientID
func (s *service) GetClientsRedirectURI(cid string) ([]string, error) {

	rc, err := s.clients.Find(core.ClientID(cid))
	if err != nil {
		fmt.Printf("while finding clientID: %v in the database error raised: %v\n", cid, err.Error())
		return []string{""}, err
	}

	return rc.RedirectURI, nil
}

// IssueIvmIDToken will create a new IDToken (according OpenIDConnect standard)
// [source](https://openid.net/specs/openid-connect-token-bound-authentication-1_0.html#rfc.section.1.1)
func (s *service) IssueIvmIDToken(uid core.UserID, cid core.ClientID) *core.IDToken {

	var iat = time.Now().Unix()
	var exp = iat + 300

	var idt = core.IDToken{
		// REQUIRED
		Iss: "https://ivmanto.com",
		Sub: string(uid),
		Aud: string(cid),
		Exp: exp,
		Iat: iat,
		// OPTIONAL
		Email:         "",
		EmailVerified: false,
	}

	return &idt
}

// NewService creates a authenticating service with necessary dependencies.
func NewService(requests core.RequestRepository,
	clients core.ClientRepository,
	users core.UserRepository,
	config config.IvmCfg) Service {

	return &service{
		requests: requests,
		clients:  clients,
		users:    users,
		config:   config,
	}
}
