package ivmanto

import (
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/dvsekhvalnov/jose2go/base64url"
)

// PublicKeySet will be used to hold the public keys sets form the
// different Identity Providers that supply authentication tokens
type PublicKeySet struct {
	IdentityProvider string
	URL              *url.URL
	HTTPClient       *http.Client
	Jwks             *JWKS
	Expires          int64
}

// JWKS is a set of JSON Web Keys (JWK) [RFC7517]
type JWKS struct {
	Keys []JWK
}

// JWK - JSON Web Key [RFC7517]
type JWK struct {
	// REQUIRED. Kty - The "kty" (key type) parameter identifies the cryptographic algorithm
	// family used with the key, such as "RSA" or "EC".  "kty" values should
	// either be registered in the IANA "JSON Web Key Types" registry
	// established by [JWA] or be a value that contains a Collision-
	// Resistant Name.  The "kty" value is a case-sensitive string.  This
	// member MUST be present in a JWK.
	Kty string

	// OPTIONAL. Use - The "use" (public key use) parameter identifies the intended use of
	// the public key.  The "use" parameter is employed to indicate whether
	// a public key is used for encrypting data or verifying the signature
	// on data.
	// Values defined by this specification are:
	// o  "sig" (signature)
	// o  "enc" (encryption
	//	Use of the "use" member is OPTIONAL, unless the application
	//	requires its presence.
	Use string

	// OPTIONAL. KeyOps - The "key_ops" (key operations) parameter identifies the operation(s)
	//  for which the key is intended to be used.  The "key_ops" parameter is
	//  intended for use cases in which public, private, or symmetric keys
	//  may be present.
	//  Its value is an array of key operation values.  Values defined by
	//  this specification are:
	//  o  "sign" (compute digital signature or MAC)
	//  o  "verify" (verify digital signature or MAC)
	//  o  "encrypt" (encrypt content)
	//  o  "decrypt" (decrypt content and validate decryption, if applicable)
	//  o  "wrapKey" (encrypt key)
	//  o  "unwrapKey" (decrypt key and validate decryption, if applicable)
	//  o  "deriveKey" (derive key)
	//  o  "deriveBits" (derive bits not to be used as a key)
	//  Other values MAY be used.  The key operation values are case-
	//  sensitive strings.  Duplicate key operation values MUST NOT be
	//  present in the array.  Use of the "key_ops" member is OPTIONAL,
	//  unless the application requires its presence.
	KeyOps string `json:"key_ops"`

	// OPTIONAL. Alg - The "alg" (algorithm) parameter identifies the algorithm intended for
	//  use with the key.  The values used should either be registered in the
	//  IANA "JSON Web Signature and Encryption Algorithms" registry
	//  established by [JWA] or be a value that contains a Collision-
	//  Resistant Name.  The "alg" value is a case-sensitive ASCII string.
	//  Use of this member is OPTIONAL.
	Alg string

	// OPTIONAL. Kid - The "kid" (key ID) parameter is used to match a specific key.  This
	//  is used, for instance, to choose among a set of keys within a JWK Set
	//  during key rollover.  The structure of the "kid" value is
	//  unspecified.  When "kid" values are used within a JWK Set, different
	//  keys within the JWK Set SHOULD use distinct "kid" values.  (One
	//  example in which different keys might use the same "kid" value is if
	//  they have different "kty" (key type) values but are considered to be
	//  equivalent alternatives by the application using them.)  The "kid"
	//  value is a case-sensitive string.  Use of this member is OPTIONAL.
	//  When used with JWS or JWE, the "kid" value is used to match a JWS or
	//  JWE "kid" Header Parameter value.
	Kid string

	// OPTIONAL. X5u - The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a
	//  resource for an X.509 public key certificate or certificate chain
	//  [RFC5280].  The identified resource MUST provide a representation of
	//  the certificate or certificate chain that conforms to RFC 5280
	//  [RFC5280] in PEM-encoded form, with each certificate delimited as
	//  specified in Section 6.1 of RFC 4945 [RFC4945].  The key in the first
	//  certificate MUST match the public key represented by other members of
	//  the JWK.  The protocol used to acquire the resource MUST provide
	//  integrity protection; an HTTP GET request to retrieve the certificate
	//  MUST use TLS [RFC2818] [RFC5246]; the identity of the server MUST be
	//  validated, as per Section 6 of RFC 6125 [RFC6125].  Use of this
	//  member is OPTIONAL.
	X5u string

	// OPTIONAL. X5c - The "x5c" (X.509 certificate chain) parameter contains a chain of one
	// or more PKIX certificates [RFC5280].  The certificate chain is
	// represented as a JSON array of certificate value strings.  Each
	// string in the array is a base64-encoded (Section 4 of [RFC4648] --
	// not base64url-encoded) DER [ITU.X690.1994] PKIX certificate value.
	// The PKIX certificate containing the key value MUST be the first
	// certificate.  This MAY be followed by additional certificates, with
	// each subsequent certificate being the one used to certify the
	// previous one.  The key in the first certificate MUST match the public
	// key represented by other members of the JWK.  Use of this member is
	// OPTIONAL.
	X5c string

	// OPTIONAL. X5t - The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a
	//  base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
	//  encoding of an X.509 certificate [RFC5280].  Note that certificate
	//  thumbprints are also sometimes known as certificate fingerprints.
	//  The key in the certificate MUST match the public key represented by
	//  other members of the JWK.  Use of this member is OPTIONAL.
	X5t string

	// OPTIONAL. - X5tS256 - The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a
	//  base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER
	//  encoding of an X.509 certificate [RFC5280].  Note that certificate
	//  thumbprints are also sometimes known as certificate fingerprints.
	//  The key in the certificate MUST match the public key represented by
	//  other members of the JWK.  Use of this member is OPTIONAL.
	X5tS256 string `json:"x5t#S256"`

	// N - modulus
	N string

	// E - public exponent
	E string
}

// Init will initiate or override the values in JWKS attribute of PublicKeySet
func (pks *PublicKeySet) Init(newKey []byte, exp int64) error {

	pks.Expires = exp

	if err := json.Unmarshal(newKey, pks.Jwks); err != nil {
		return InvalidPubliKeySet(err)
	}
	return nil
}

// GetKid - returns a JWK found by its kid
func (pks *PublicKeySet) GetKid(kid string) (JWK, error) {
	if len(pks.Jwks.Keys) == 0 {
		return JWK{}, InvalidPubliKeySet(errors.New("Empty set of JWKs"))
	}
	var n, e string
	var jwk JWK
	for _, jwk := range pks.Jwks.Keys {
		if jwk.Kid == kid && jwk.Kty == "RSA" {
			n = jwk.N
			e = jwk.E
			break
		}
	}
	if n == "" && e == "" {
		return JWK{}, InvalidPubliKeySet(errors.New("JWK not found by the provided kid"))
	}
	return jwk, nil
}

// GetKidNE - returns modulus N and pblic exponent E as big.Int and int respectively
func (pks *PublicKeySet) GetKidNE(kid string) (*big.Int, int, error) {
	if len(pks.Jwks.Keys) == 0 {
		return nil, 0, InvalidPubliKeySet(errors.New("Empty set of JWKs"))
	}
	var n, e string
	for _, jwk := range pks.Jwks.Keys {
		if jwk.Kid == kid && jwk.Kty == "RSA" {
			n = jwk.N
			e = jwk.E
			break
		}
	}
	if n == "" && e == "" {
		return nil, 0, InvalidPubliKeySet(errors.New("JWK not found by the provided kid"))
	}

	nb, err := base64url.Decode(n)
	if err != nil {
		return nil, 0, InvalidPubliKeySet(errors.New("invalid JWK modulus"))
	}
	// TODO add a condition to check if the jwk.e is not
	ei := 65537

	bn := new(big.Int)
	bn = bn.SetBytes(nb)
	return bn, ei, nil
}

// LenJWKS return the length of the array of JWKs
func (pks *PublicKeySet) LenJWKS() int {
	if pks == nil {
		return 0
	}
	return len(pks.Jwks.Keys)
}

// NewPublicKeySet creates a new set of Public Key for each of the suported
// Identity Vendors.
func NewPublicKeySet(identityProvider string) *PublicKeySet {
	jwk := JWK{Kty: ""}
	jwks := JWKS{Keys: []JWK{jwk}}

	return &PublicKeySet{
		IdentityProvider: identityProvider,
		URL:              &url.URL{},
		HTTPClient: &http.Client{
			Timeout: time.Second * 30,
		},
		Jwks:    &jwks,
		Expires: 0,
	}
}

// PublicKeySetRepository provides access a PKS store.
type PublicKeySetRepository interface {
	// Store will override a public key set if such already exists (identified by URL)
	Store(pks *PublicKeySet) error
	Find(IdentityProvider string) (*PublicKeySet, error)
	FindAll() []*PublicKeySet
}
