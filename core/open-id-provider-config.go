package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/dasiyes/ivmconfig/src/pkg/config"
)

// ProviderName is representing the name of OIDConnect Provider
type ProviderName string

// OIDProvider represents an OpenID Identity Provider
type OIDProvider struct {
	ProviderName ProviderName
	Oidc         *config.OpenIDConfiguration
}

// NewOIDProvider creates a new OpenID Provider object
func NewOIDProvider(identityProvider ProviderName) *OIDProvider {

	var oidc config.OpenIDConfiguration

	return &OIDProvider{
		ProviderName: identityProvider,
		Oidc:         &oidc,
	}
}

// OIDProviderRepository provides access to a OIDConfig store.
type OIDProviderRepository interface {
	Store(ip *OIDProvider) error
	Find(IdentityProvider ProviderName) (*OIDProvider, error)
	FindAll() []*OIDProvider
}

// IDToken according to OpenID Connect spec - point 2.  ID Token
//
// The primary extension that OpenID Connect makes to OAuth 2.0 to enable End-Users to be Authenticated is the ID Token data structure. The ID Token is a security token that contains Claims about the Authentication of an End-User by an Authorization Server when using a Client, and potentially other requested Claims. The ID Token is represented as a JSON Web Token (JWT) [JWT].
//
// The following Claims are used within the ID Token for all OAuth 2.0 flows used by OpenID Connect:
type IDToken struct {
	// REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
	Iss string

	// REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
	Sub string

	// REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
	Aud string

	// REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing. The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time. See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular.
	Exp int64

	// REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	Iat int64

	// Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time. When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)
	AuthTime int64 `json:"auth_time,omitempty"`

	// String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified from the Authentication Request to the ID Token. If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request. If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request. Authorization Servers SHOULD perform no other processing on nonce values used. The nonce value is a case sensitive string.
	Nonce string

	// OPTIONAL. Authentication Context Class Reference. String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied. The value "0" indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1. Authentication using a long-lived browser cookie, for instance, is one example where the use of "level 0" is appropriate. Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value. (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value; registered names MUST NOT be used with a different meaning than that which is registered. Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific. The acr value is a case sensitive string.
	Acr string

	// OPTIONAL. Authentication Methods References. JSON array of strings that are identifiers for authentication methods used in the authentication. For instance, values might indicate that both password and OTP authentication methods were used. The definition of particular values to be used in the amr Claim is beyond the scope of this specification. Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific. The amr value is an array of case sensitive strings.
	Amr string

	// OPTIONAL. Authorized party - the party to which the ID Token was issued. If present, it MUST contain the OAuth 2.0 Client ID of this party. This Claim is only needed when the ID Token has a single audience value and that audience is different than the authorized party. It MAY be included even when the authorized party is the same as the sole audience. The azp value is a case sensitive string containing a StringOrURI value.
	Azp string

	// Email - the email address of the user. [Google IDToken]
	Email string `json:"email,omitempty"`

	// EmailVerified flag, indicates that the user's email address is verified on the IP server side. [Google IDToken]
	EmailVerified bool `json:"email_verified,omitempty"`

	// Name - both names [Google IDToken]
	Name string `json:"name,omitempty"`

	// FirstName [Google IDToken]
	FirstName string `json:"given_name,omitempty"`

	// FamilyName [Google IDToken]
	FamilyName string `json:"family_name,omitempty"`

	// Jti - token ID [Google IDToken]
	Jti string `json:"jti,omitempty"`

	// Picture - url for the user's profile avatar [Google IDToken]
	Picture string `json:"picture,omitempty"`
}

// Valid function performs an validation check that match the OpenID Connect specification for validating ID Token
func (it *IDToken) Valid() error {

	tn := time.Now().Unix()

	if it.Iss == "" || !strings.HasPrefix(strings.ToLower(it.Iss), "https") {
		return fmt.Errorf("%s, %v", "empty or invalid `Iss` value | ", ErrInvalidIDToken)
	}

	if it.Sub == "" || len(it.Sub) > 255 {
		return fmt.Errorf("%s, %v", "empty or invalid `Sub` value | ", ErrInvalidIDToken)
	}

	if it.Aud == "" {
		return fmt.Errorf("%s, %v", "empty `Aud` value | ", ErrInvalidIDToken)
	}

	if it.Exp < tn+60 {
		return fmt.Errorf("%s, %v", "token expired | ", ErrInvalidIDToken)
	}

	if it.Iat >= tn+1 {
		return fmt.Errorf("invalid `Iat` value %d vs now %d| error: %v", it.Iat, tn, ErrInvalidIDToken)
	}

	return nil
}
