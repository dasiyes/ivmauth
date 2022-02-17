package core

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
type IvmantoATClaims struct {
	Iss  string `json:"iss"`
	Sub  string `json:"sub"`
	Aud  string `json:"aud"`
	Exp  int64  `json:"exp"`
	Nbf  int64  `json:"nbf"`
	Iat  int64  `json:"iat"`
	Jti  string `json:"jti"`
	Name string `json:"name"`
}

// TODO [dev]: review if this method is required?
// Validate the access token issued by
func (c *IvmantoATClaims) Valid() error {

	return nil
}
