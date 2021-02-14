package ivmanto

// ProviderName is representing the name of OIDConnect Provider
type ProviderName string

// OpenIDConfiguration is Ivmanto's object to support OpenID Connect
// according to [this spec](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse)
//
// The response is a set of Claims about the OpenID Provider's configuration, including all necessary endpoints and public key location information. A successful response MUST use the 200 OK HTTP status code and return a JSON object using the application/json content type that contains a set of Claims as its members that are a subset of the Metadata values defined in Section 3. Other Claims MAY also be returned.
//
// Claims that return multiple values are represented as JSON arrays. Claims with zero elements MUST be omitted from the response.
type OpenIDConfiguration struct {
	// "https://server.example.com"
	Issuer string

	// "https://server.example.com/connect/authorize"
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// "https://server.example.com/connect/token"
	TokenEndpoint string `json:"token_endpoint"`

	// "https://oauth2.googleapis.com/revoke
	RevocationEndpoint string `json:"revocation_endpoint"`

	// ["client_secret_basic", "private_key_jwt"]
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`

	// ["RS256", "ES256"]
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`

	// "https://server.example.com/connect/userinfo",
	UserinfoEndpoint string `json:"userinfo_endpoint"`

	// "https://server.example.com/connect/check_session"
	CheckSessionIframe string `json:"check_session_iframe"`

	// "https://server.example.com/connect/end_session"
	EndSessionEndpoint string `json:"end_session_endpoint"`

	// "https://server.example.com/jwks.json"
	JWKSURI string `json:"jwks_uri"`

	// "https://server.example.com/connect/register"
	RegistrationEndpoint string `json:"registration_endpoint"`

	// ["openid", "profile", "email", "address", "phone", "offline_access"]
	ScopesSupported []string `json:"scopes_supported"`

	// ["code", "code id_token", "id_token", "token id_token"]
	ResponseTypesSupported []string `json:"response_types_supported"`

	// ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"]
	ArcValuesSupported []string `json:"acr_values_supported"`

	// ["public", "pairwise"]
	SubjectTypesSupported []string `json:"subject_types_supported"`

	// ["RS256", "ES256", "HS256"]
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported"`

	// ["RSA1_5", "A128KW"]
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported"`

	// ["A128CBC-HS256", "A128GCM"]
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported"`

	// ["RS256", "ES256", "HS256"]
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// ["RSA1_5", "A128KW"]
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported"`

	// ["A128CBC-HS256", "A128GCM"]
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported"`

	// ["none", "RS256", "ES256"]
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported"`

	// ["page", "popup"]
	DisplayValuesSupported []string `json:"display_values_supported"`

	// ["normal", "distributed"]
	ClaimTypesSupported []string `json:"claim_types_supported"`

	// ["sub", "iss", "auth_time", "acr","name", "given_name", "family_name", "nickname", "profile", "picture", "website", "email","email_verified", "locale", "zoneinfo", "http://example.info/claims/groups"]
	ClaimsSupported []string `json:"claims_supported"`

	// true
	ClaimsParameterSupported bool `json:"claims_parameter_supported"`

	// "http://server.example.com/connect/service_documentation.html"
	ServiceDocumentation string `json:"service_documentation"`

	// ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
	URILocalesSupported []string `json:"ui_locales_supported"`

	// ["plain", "S256"]
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

// OIDProvider represents an OpenID Identity Provider
type OIDProvider struct {
	ProviderName ProviderName
	Oidc         OpenIDConfiguration
}

// NewOIDProvider creates a new OpenID Provider object
func NewOIDProvider(identityProvider ProviderName) *OIDProvider {

	var oidc OpenIDConfiguration

	return &OIDProvider{
		ProviderName: identityProvider,
		Oidc:         oidc,
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
	AuthTime int64 `json:"auth_time"`

	// String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified from the Authentication Request to the ID Token. If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request. If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request. Authorization Servers SHOULD perform no other processing on nonce values used. The nonce value is a case sensitive string.
	Nonce string

	// OPTIONAL. Authentication Context Class Reference. String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied. The value "0" indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1. Authentication using a long-lived browser cookie, for instance, is one example where the use of "level 0" is appropriate. Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value. (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value; registered names MUST NOT be used with a different meaning than that which is registered. Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific. The acr value is a case sensitive string.
	Acr string

	// OPTIONAL. Authentication Methods References. JSON array of strings that are identifiers for authentication methods used in the authentication. For instance, values might indicate that both password and OTP authentication methods were used. The definition of particular values to be used in the amr Claim is beyond the scope of this specification. Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific. The amr value is an array of case sensitive strings.
	Amr string

	// OPTIONAL. Authorized party - the party to which the ID Token was issued. If present, it MUST contain the OAuth 2.0 Client ID of this party. This Claim is only needed when the ID Token has a single audience value and that audience is different than the authorized party. It MAY be included even when the authorized party is the same as the sole audience. The azp value is a case sensitive string containing a StringOrURI value.
	Azp string

	// Valid is internal flag to indicate if application validation process has completed successfully
	Valid bool
}

// NewIDToken creates an empty ID Token
// TODO: Consider - may be this is not required at all...
func NewIDToken() *IDToken {
	return &IDToken{
		Iss:      "",
		Sub:      "",
		Aud:      "",
		Exp:      0,
		Iat:      0,
		AuthTime: 0,
		Nonce:    "",
		Acr:      "",
		Amr:      "",
		Azp:      "",
		Valid:    false,
	}
}

// Validate function performs an validation check that match the OpenID Connect specification for validating ID Token
func (it *IDToken) Validate() {

}
