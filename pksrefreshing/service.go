package pksrefreshing

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ivmanto.dev/ivmauth/ivmanto"
)

// ErrInvalidArgument is returned when one or more arguments are invalid.
var ErrInvalidArgument = errors.New("invalid argument")

// Service is the interface that provides the service's methods.
type Service interface {
	// RefreshPKS suposed to connect and get a new, fresh set of
	// Public Keys (jwks) for the given provider.
	NewPKS(identityProvider string, pkURL string) error

	// GetRSAPublicKey gets the jwks, finds the JWK by kid and returns it as rsa.PublicKey format
	GetRSAPublicKey(identityProvider string, kid string) (rsa.PublicKey, error)

	// GetPKSCache - finds and returns PKS from the cache, if available
	GetPKSCache(identityProvider string, pkURL string) (*ivmanto.PublicKeySet, error)
}

type service struct {
	keyset ivmanto.PublicKeySetRepository
}

// NewPKS creates new Public Key Set
func (s *service) NewPKS(identityProvider string, pkURL string) error {
	if len(identityProvider) == 0 || len(pkURL) == 0 {
		return ErrInvalidArgument
	}
	urlval, err := url.Parse(pkURL)
	if err != nil {
		return ErrInvalidArgument
	}

	pks := ivmanto.NewPublicKeySet(identityProvider, urlval)
	jwks, exp, err := downloadJWKS(pks)
	if err != nil {
		return err
	}
	if err := pks.Init(jwks, exp); err != nil {
		return err
	}
	if err := s.keyset.Store(pks); err != nil {
		return err
	}
	return nil
}

// GetRSAPublicKey converts the jwks into rsaPublicKey and returns it back
func (s *service) GetRSAPublicKey(identityProvider string, kid string) (rsa.PublicKey, error) {

	pks, err := s.keyset.Find(identityProvider)
	if err != nil {
		return rsa.PublicKey{}, errors.New("Error while searching for PK: " + err.Error())
	}
	n, e, err := pks.GetKidNE(kid)
	if err != nil {
		return rsa.PublicKey{}, errors.New("Error getting modulus and public exponent: " + err.Error())
	}
	rsaPK := rsa.PublicKey{
		N: n,
		E: e,
	}
	return rsaPK, nil
}

// GetPKSCache finds the PKS and returns it from the cache. If not found, calls NewPKS
//  to download the keys from the URL
func (s *service) GetPKSCache(identityProvider string, pkURL string) (*ivmanto.PublicKeySet, error) {

	pks, err := s.keyset.Find(identityProvider)
	if err != nil {
		return &ivmanto.PublicKeySet{}, errors.New("Error while searching for PK: " + err.Error())
	}
	return pks, nil
}

// NewService creates a authenticating service with necessary dependencies.
func NewService(pksr ivmanto.PublicKeySetRepository) Service {
	return &service{
		keyset: pksr,
	}
}

// downloadJWKS - download jwks from the URL for the respective Identity provider
func downloadJWKS(pks *ivmanto.PublicKeySet) ([]byte, int64, error) {
	resp, err := pks.HTTPClient.Get(pks.URL.String())
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, 0, errors.New("Error while getting JWKS from identity provider url")
	}

	jwksb, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	// =============================================
	// For Cache-Control expire time calculation
	var exp int64

	cc := resp.Header.Get("Cache-Control")
	ccp := strings.Split(cc, ",")
	for _, p := range ccp {
		if strings.HasPrefix(p, "max-age=") {
			mapr := strings.Split(p, "=")
			ma, err := strconv.ParseInt(mapr[1], 10, 64)
			if err != nil {
				// TODO: logging log.Printf("WARNING: Cache-Control max-age value is not an int.")
				ma = 0
			}
			exp += ma
		}
	}
	exp += time.Now().Unix()

	return jwksb, exp, nil
}
