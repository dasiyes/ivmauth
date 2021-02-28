package ivmanto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// AccessToken represents the object returned to the requestor
// in case of successful authentication for the Ivmanto's realm
//
// The definition is according to [RFC6749] section 5.1
type AccessToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	// The Scope property can be omited from the AccessToken if match the authentication request scope
	Scope []string `json:"scope,omitempty"`
}

// The object with standard JWT claims [RFC7519] for embiding into the Ivamnto's AT
type ivmantoATClaims struct {
	iss string
	sub string
	aud string
	exp int64
	nbf int64
	iat int64
	jti string
}

// ATCfg is the configuration object for the Access Token
type ATCfg struct {
	Validity  int
	Realm     string
	Alg       string
	IssuerVal string `yaml:"issuer"`
}

// NewIvmantoAccessToken creates a new response to a successful authentication request.
// @realm could be comma-separated list of application that accept this AT.\
// default signing method alg is RS256; default realm if missing is ivm;
func NewIvmantoAccessToken(scp *[]string, atConfig *ATCfg) *AccessToken {

	var realm = atConfig.Realm
	var validity = atConfig.Validity
	var alg = atConfig.Alg
	var issval = atConfig.IssuerVal
	var sm jwt.SigningMethodRSA

	if len(realm) < 3 {
		realm = "ivm"
	}
	if issval == "" {
		issval = "https://accounts.ivmanto.com"
	}

	clm := newIvmATC(validity, realm, issval)

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

	at, err := newJWToken(clm, &sm)
	if err != nil {
		return nil
	}

	// TODO: [IVM-1] generate and save the refresh token (as part of the user management)
	rtkn := ""

	return &AccessToken{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    validity,
		RefreshToken: rtkn,
		Scope:        *scp,
	}
}

// newIvmATC generates a new ivmantoATClaims set. @validity in seconds
func newIvmATC(validity int, realm string, issval string) *ivmantoATClaims {

	tn := time.Now().Unix()
	tid := genTID(realm[:3])

	// TODO: Move the iss and aud values into a configuration/db document for abstraction of the service
	// TODO: consider to change the content of the AUD. The meaing should be the receiver of the token should identify itslef withing the value of AUD.
	return &ivmantoATClaims{
		iss: issval,
		sub: "",
		aud: "realm:[" + realm + "]",
		exp: tn + int64(validity),
		iat: tn,
		nbf: tn,
		jti: tid,
	}
}

// to satisfy jwt-go package requirements for Claims object
func (c *ivmantoATClaims) Valid() error {
	// TODO: review if input claims needs to be validated
	return nil
}

// Issue a new JWT Token with respective Signing method and claims
func newJWToken(claims jwt.Claims, sm jwt.SigningMethod) (string, error) {

	var token *jwt.Token
	var tkn string

	switch sm.Alg() {
	case "RS256":

		// TODO: think about how to use this key and how to roate it !!!
		// TODO: implement kid ?!
		key, err := rsa.GenerateKey(rand.Reader, 2048)

		if err != nil {
			return "", err
		}
		token = jwt.NewWithClaims(sm, claims)
		tkn, err = token.SignedString(key)
		if err != nil {
			return "", err
		}
		// TODO: at this point implement method to store the key along side with the requestor (sub claim). This is to be used for further usage for signing for the same requestor?
		return tkn, nil
	default:
		return "", ErrUnknownMethod
	}
}
