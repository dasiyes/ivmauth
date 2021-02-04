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

	GetRSAPublicKey(identityProvider string) (rsa.PublicKey, error)
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
func (s *service) GetRSAPublicKey(identityProvider string) (rsa.PublicKey, error) {

	// TODO: compose the correct rsa.PublicKey object
	pk := rsa.PublicKey{}
	return pk, nil
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
