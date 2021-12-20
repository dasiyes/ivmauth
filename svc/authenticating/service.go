package authenticating

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/dataservice/firestoredb"
	rph "github.com/dasiyes/ivmauth/pkg/rsapemhelps"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
	"github.com/dasiyes/ivmconfig/src/pkg/config"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

// TODO [dev]: Review the service concept against the checklist below:
// **Authentication Framework Evaluation Checklist**
// [x] Provides the ability to exchange credentials (username/password, token, and so on) for a valid session.
// [x] Supports proper session management (www.owasp.org/index.php/Session_Management_Cheat_Sheet).
// [ ] Lets users opt in to two-factor authentication.
// [x] In a browser-based environment, properly marks the session cookie as HTTPOnly (www.owasp.org/index.php/HttpOnly) and secure (www.owasp.org/index.php/SecureFlag).
// [x] Provides support for Cross-Site Request Forgery (CSRF; goo.gl/TwcSJX) protection/ defenses.
//		 - nosurf package implemented for Login Form.
//		 [ ] to implement nosurf or alternative method for any new methods that change the state!!!
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

	// ValidateAccessToken - will validate the provided Access Token. OpenID Connect IDTokens will bealso supported only from listed /configured OIDC providers.
	ValidateAccessToken(at, oidpn string) error

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
	IssueIvmIDToken(subCode string, cid core.ClientID) *core.IDToken
}

type service struct {
	pkr      pksrefreshing.Service
	requests core.RequestRepository
	kj       core.KJR
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
		return valid, fmt.Errorf("error finding user %s: %v", email, err.Error())
	}
	if usr.Status != core.EntryStatusActive {
		return valid, fmt.Errorf("the user %s status is: %s. Must be `Active`", email, usr.Status.String())
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

	// NewIvmantoAccessToken creates a new response to a successful authentication request.
	// @realm could be comma-separated list of application that accept this AT.\
	// default signing method alg is RS256; default realm if missing is ivm;

	atcfg := s.config.GetATC()
	scopes := client.Scopes

	var realm = atcfg.Realm
	var validity = atcfg.Validity
	var alg = atcfg.Alg
	var issval = atcfg.Issuer
	var oidpn = atcfg.OIDProviderName
	var sm jwt.SigningMethodRSA

	if len(realm) < 3 {
		realm = "ivm"
	}
	if issval == "" {
		issval = "https://accounts.ivmanto.com"
	}
	if oidpn == "" {
		oidpn = "ivmanto"
	}

	clm := newIvmATC(validity, realm, issval, oidt.Sub)
	rtclm := newIvmATC(0, realm, issval, oidt.Sub)

	switch alg {
	case "RS256":
		sm = jwt.SigningMethodRSA{
			Name: "RS256",
			Hash: crypto.SHA256,
		}
	default:
		sm = jwt.SigningMethodRSA{
			Name: "RS256",
			Hash: crypto.SHA256,
		}
	}

	at, err := s.newJWToken(clm, &sm, oidpn, oidt.Sub)
	if err != nil {
		return nil, fmt.Errorf("error on create newJWToken [at]: %v", err)
	}
	rtkn, err := s.newJWToken(rtclm, &sm, oidpn, oidt.Sub)
	if err != nil {
		return nil, fmt.Errorf("error on create newJWToken [rtkn]: %v", err)
	}

	ato := core.AccessToken{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    validity,
		RefreshToken: rtkn,
		Scope:        scopes,
	}

	return &ato, nil
}

// ValidateAccessToken - will validate the provided Access Token. OpenID Connect IDTokens will be also supported only from listed / configured OIDC providers.
// @at - Access Token. Can be also openID Connect IDToken.
// @oidpn - openID provider name
func (s *service) ValidateAccessToken(at, oidpn string) error {

	// [x] step-1: If the provider is registred
	if ok, err := s.pkr.OIDPExists(oidpn); !ok && err != nil {
		return fmt.Errorf("while checking if the oidpn [%s] is a registered provider, raised error: %v", oidpn, err)
	}

	tkn, oidtoken, err := validateIDToken(at, oidpn, s.pkr)
	if err != nil {
		return fmt.Errorf("[ValidateAccessToken] token: %#v, idtoken: %#v, while validating access token -error: %#v", tkn, oidtoken, err)
	}

	if tkn.Valid {
		if err := oidtoken.Valid(); err != nil {
			fmt.Printf("error validating idToken %+v", oidtoken)
		}
	} else {
		// the tkn is NOT valid - return error
		return fmt.Errorf("invalid access token for provider %s", oidpn)
	}

	return nil
}

// TODO [dev]: review and remove becuase the registering User is done in the svc/registering service
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

	nUsr.Status = core.EntryStatus(core.EntryStatusDraft)

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
			nUsr.Status = core.EntryStatus(core.EntryStatusDraft)
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
func (s *service) IssueIvmIDToken(subCode string, cid core.ClientID) *core.IDToken {

	var iat = time.Now().Unix()
	var exp = iat + 3600

	var idt = core.IDToken{
		// REQUIRED
		Iss: "https://ivmanto.com",
		Sub: subCode,
		Aud: string(cid),
		Exp: exp,
		Iat: iat,
		// OPTIONAL
		Email:         "",
		EmailVerified: false,
	}

	return &idt
}

// Issue a new JWT Token with respective Signing method and claims
// [ ] Review this possible cache solution: https://github.com/ReneKroon/ttlcache
func (s *service) newJWToken(claims jwt.Claims, sm jwt.SigningMethod, oidpn, subCode string) (string, error) {

	var token *jwt.Token
	var tkn string
	var pks *core.PublicKeySet
	var err error
	var kid string

	// TODO [dev]: take the private key for sign the token.
	pks, err = s.pkr.GetPKSCache(oidpn)
	if err != nil {
		return "", fmt.Errorf("error retrieving PKS for oidpn %s err: %v", oidpn, err)
	}

	// Check if the key rotator process has created a new key, third key (at index 2), if not take the current active key (at index 1)
	avk := pks.LenJWKS()
	if avk > 2 {
		// Get the key id for the new key and retrive the private key from the key journal
		kid = pks.GetKidByIdx(2)
	} else if avk == 2 {
		// Get the key id for the current active key and retrive the private key from the key journal
		kid = pks.GetKidByIdx(1)
	} else {
		return "", fmt.Errorf("error identifing the active signing key for oidpn %s. error: JWKS has less than 2 keys", oidpn)
	}

	switch sm.Alg() {
	case "RS256":

		// retrieve the private key to use for signing the token
		pkstr, err := s.kj.GetSigningKey(kid)
		if err != nil {
			return "", fmt.Errorf("error retrieving signing key id %s, error: %v", kid, err)
		}

		key, err := rph.ParseRSAPrivateKeyFromPEM(pkstr)
		if err != nil {
			return "", fmt.Errorf("error parsing signing key id %s from PEM, error: %v", kid, err)
		}

		// Create the new token with claims
		token = jwt.NewWithClaims(sm, claims)

		// adding the key ID to the token header
		token.Header["kid"] = kid

		// adding the sub value as subject registered within the openId provider
		token.Header["sub"] = subCode

		tkn, err = token.SignedString(key)
		if err != nil {
			return "", fmt.Errorf("error while signing the token with key id %s, error: %v", kid, err)
		}
		return tkn, nil
	default:
		return "", core.ErrUnknownMethod
	}
}

// NewService creates a authenticating service with necessary dependencies.
func NewService(pkr pksrefreshing.Service,
	requests core.RequestRepository,
	kj core.KJR,
	clients core.ClientRepository,
	users core.UserRepository,
	config config.IvmCfg) Service {

	return &service{
		pkr:      pkr,
		requests: requests,
		kj:       kj,
		clients:  clients,
		users:    users,
		config:   config,
	}
}

// newIvmATC generates a new ivmantoATClaims set.
// @validity in seconds
func newIvmATC(validity int, realm, issval, subCode string) *core.IvmantoATClaims {

	tn := time.Now().Unix()
	tid := core.GenTID(realm[:3])

	// [x]: Move the iss and aud values into a configuration/db document for abstraction of the service
	// [x]: consider to change the content of the AUD. The meaing should be the receiver of the token should identify itslef withing the value of AUD.
	return &core.IvmantoATClaims{
		Iss: issval,
		Sub: subCode,
		// [ ] Check if the value of `Aud` must be replaced by clienID?!?
		Aud: "realm:[" + realm + "]",
		Exp: tn + int64(validity),
		Iat: tn,
		Nbf: tn,
		Jti: tid,
	}
}
