package core

import (
	"crypto/rand"
	"crypto/rsa"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/segmentio/ksuid"
)

// PublicKeySetRepository provides access a PKS store.
type PublicKeySetRepository interface {
	// Store will override a public key set if such already exists (identified by URL)
	Store(pks *PublicKeySet) error
	Find(IdentityProvider string) (*PublicKeySet, error)
	FindDeadline(kid string) (int64, error)
	FindAll() []*PublicKeySet
}

// PublicKeySet will be used to hold the public keys sets form the
// different Identity Providers that supply authentication tokens
type PublicKeySet struct {
	IdentityProvider string
	URL              string
	HTTPClient       *http.Client
	Jwks             *JWKS
	KeyJournal       map[string]interface{}
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
		fmt.Printf("pks.JWKS: %#v", pks.Jwks)
		return InvalidPublicKeySet(err)
	}
	return nil
}

// GetKid - returns a JWK found by its kid
func (pks *PublicKeySet) GetKid(kid string) (JWK, error) {
	if len(pks.Jwks.Keys) == 0 {
		return JWK{}, InvalidPublicKeySet(errors.New("empty set of JWKs"))
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
		return JWK{}, InvalidPublicKeySet(errors.New("JWK not found by the provided kid"))
	}
	return jwk, nil
}

// GetCurrentKid - will return the kid as string for the key at index 1 of the Jwks
func (pks *PublicKeySet) GetCurrentKid() string {
	var current_kid string
	for i, jwk := range pks.Jwks.Keys {
		if i == 1 {
			current_kid = jwk.Kid
		}
	}
	return current_kid
}

// GetKidNE - returns modulus N and pblic exponent E as big.Int and int respectively
func (pks *PublicKeySet) GetKidNE(kid string) (*big.Int, int, error) {
	if len(pks.Jwks.Keys) == 0 {
		return nil, 0, InvalidPublicKeySet(errors.New("empty set of JWKs"))
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
		return nil, 0, InvalidPublicKeySet(errors.New("JWK not found by the provided kid"))
	}

	// nb, err := base64url.Decode(n)
	nb, err := b64.URLEncoding.DecodeString(n)
	if err != nil {
		return nil, 0, InvalidPublicKeySet(errors.New("invalid JWK modulus"))
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

// AddJWK will generate new private key and from it will add a new JWK into JWKS
func (pks *PublicKeySet) AddJWK(sm jwt.SigningMethod, validity int64) error {

	var jwks = pks.LenJWKS()
	if jwks > 2 {
		return fmt.Errorf("There are already %d JWKeys", jwks)
	}

	var prvkey *rsa.PrivateKey
	var pk rsa.PublicKey

	var err error
	var kty, use, kid string

	switch sm.Alg() {
	case "RS256":
		kty = "RSA"
		use = "sig"
		kid = ksuid.New().String()
		prvkey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generating key error %#v", err)
		}
		pk = prvkey.PublicKey

	default:
		return ErrUnknownMethod
	}

	// [x]: fullfill the JWK with attributes including from the prvkey above
	var newJWK = JWK{
		Kty: kty,
		Use: use,
		Kid: kid,
		Alg: sm.Alg(),
		N:   nToString(pk.N),
		E:   expToString(pk.E),
	}

	// [x]: fill the KeyJournal - as KEY will be the kid value and as VALUE will be the deadline value
	pks.KeyJournal[kid] = time.Now().Unix() + validity

	pks.Jwks.Keys = append(pks.Jwks.Keys, newJWK)

	return nil
}

// NewPublicKeySet creates a new set of Public Key for each of the suported
// Identity Vendors.
func NewPublicKeySet(identityProvider string) *PublicKeySet {

	jwk := JWK{Kty: "RSA"}
	jwks := JWKS{Keys: []JWK{jwk}}

	return &PublicKeySet{
		IdentityProvider: identityProvider,
		URL:              "",
		HTTPClient: &http.Client{
			Timeout: time.Second * 30,
		},
		Jwks:       &jwks,
		KeyJournal: map[string]interface{}{"n.a.": time.Now().Unix()},
		Expires:    0,
	}
}

// Public key (JWK) exponent parameter (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-algorithms-31#section-6.3.1.2)
//
// The "e" (exponent) member contains the exponent value for the RSA
// public key.  It is represented as the base64url encoding of the
// value's unsigned big endian representation as an octet sequence.  The
// octet sequence MUST utilize the minimum number of octets to represent
// the value.  For instance, when representing the value 65537, the
// octet sequence to be base64url encoded MUST consist of the three
// octets [1, 0, 1].
func expToString(pkE int) string {

	var ebs = encodeUint(uint64(pkE))
	eStr := b64.URLEncoding.EncodeToString(ebs)
	return eStr
}

// Custom transform of uint to []byte
// source: (https://stackoverflow.com/questions/16888357/convert-an-integer-to-a-byte-array)
func encodeUint(x uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, x)
	return buf[bits.LeadingZeros64(x)>>3:]
}

// Public Key (JWK) N (modulus) parameter (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-algorithms-31#section-6.3.1.1)
//
// The "n" (modulus) member contains the modulus value for the RSA
// public key.  It is represented as the base64url encoding of the
// value's unsigned big endian representation as an octet sequence.  The
// octet sequence MUST utilize the minimum number of octets to represent
// the value.
func nToString(n *big.Int) string {
	nb := n.Bytes()
	nb64 := b64.URLEncoding.WithPadding(b64.NoPadding).EncodeToString(nb)
	return nb64
}
