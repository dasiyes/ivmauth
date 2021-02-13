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
