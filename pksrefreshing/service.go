package pksrefreshing

import (
	"errors"
	"io/ioutil"
	"math/big"
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
	// TODO: consider to turn it into private function. It seems it is not really used out of the package
	NewPKS(identityProvider string, pkURL string) error

	// GetRSAPublicKey gets the jwks, finds the JWK by kid and returns it as rsa.PublicKey format
	GetRSAPublicKey(identityProvider string, kid string) (*big.Int, int, error)

	// GetPKSCache - finds and returns PKS from the cache, if available
	GetPKSCache(identityProvider string, pkURL string) (*ivmanto.PublicKeySet, error)

	// DownloadPKSinCache - will check the cache for not expired PKS if not found will download it. Otherwise do nothing.
	// This feature to be used as preliminary download feature
	DownloadPKSinCache(identityProvider string)
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
func (s *service) GetRSAPublicKey(identityProvider string, kid string) (n *big.Int, e int, err error) {

	pks, err := s.keyset.Find(identityProvider)
	if err != nil {
		return &big.Int{}, 0, errors.New("Error while searching for PK: " + err.Error())
	}
	n, e, err = pks.GetKidNE(kid)
	if err != nil {
		return &big.Int{}, 0, errors.New("Error getting modulus and public exponent: " + err.Error())
	}
	// rsaPK := rsa.PublicKey{
	// 	N: n,
	// 	E: e,
	// }
	return n, e, nil
}

// DownloadPKSinCache - will check the cache for not expired PKS if not found will download it. Otherwise do nothing.
// This feature to be used as preliminary download feature
func (s *service) DownloadPKSinCache(identityProvider string) {
	var pkURL string
	// TODO: automate the process of getting the jwks_uri from https://accounts.google.com/.well-known/openid-configuration
	switch identityProvider {
	case "google":
		pkURL = "https://www.googleapis.com/oauth2/v3/certs"
	}

	// Check the cache for PKS
	pks, err := s.keyset.Find(identityProvider)
	if err != nil && err.Error() == "key not found" {
		err = nil
		// Not found - download it again from the providers url
		err = s.NewPKS(identityProvider, pkURL)
		if err != nil {
			return
		}
	}

	// Found in cache in the searches above - check if not expired
	if pks.Expires < time.Now().Unix()+int64(time.Second*60) {
		// has expired or will expire in the next minute - try to download it again
		err = s.NewPKS(identityProvider, pkURL)
		if err != nil {
			// error when downloading it
			return
		}
	}
}

// GetPKSCache finds the PKS and returns it from the cache. If not found, calls NewPKS
//  to download the keys from the URL
func (s *service) GetPKSCache(identityProvider string, pkURL string) (*ivmanto.PublicKeySet, error) {

	// TODO: automate the process of getting the jwks_uri from https://accounts.google.com/.well-known/openid-configuration
	// Get the pks from the cache
	pks, err := s.keyset.Find(identityProvider)
	if err != nil && err.Error() == "key not found" {
		err = nil
		// Not found - download it again from the providers url
		err = s.NewPKS(identityProvider, "https://www.googleapis.com/oauth2/v3/certs")
		if err != nil {
			// error when downloading it - return empty pks and error
			return &ivmanto.PublicKeySet{}, errors.New("Error while creating a new PKS: " + err.Error())
		}
		// Try again to find it in cache - once the download has been called
		pks, err = s.keyset.Find(identityProvider)
		if err != nil {
			// Not found again - return empty pks and error
			return &ivmanto.PublicKeySet{}, err
		}
	}
	// Found in cache in the searches above - check if not expired
	if pks.Expires < time.Now().Unix()+int64(time.Second*30) {
		// has expired - try to download it again
		err = s.NewPKS("google", "https://www.googleapis.com/oauth2/v3/certs")
		if err != nil {
			// error when downloading it - return empty pks and error
			return &ivmanto.PublicKeySet{}, errors.New("Error while creating a new PKS: " + err.Error())
		}
		// Try to find it again after the new download
		pks, err = s.keyset.Find(identityProvider)
		if err != nil {
			// Not found again - return empty pks and error
			return &ivmanto.PublicKeySet{}, err
		}
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
