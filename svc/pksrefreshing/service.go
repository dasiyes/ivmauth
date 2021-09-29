package pksrefreshing

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Service is the interface that provides the service's methods.
type Service interface {

	// InitOIDProviders
	InitOIDProviders()

	// GetRSAPublicKey gets the jwks, finds the JWK by kid and returns it as rsa.PublicKey format
	GetRSAPublicKey(identityProvider string, kid string) (*big.Int, int, error)

	// GetPKSCache - finds and returns PKS from the cache, if available
	GetPKSCache(identityProvider string) (*ivmanto.PublicKeySet, error)

	// DownloadPKSinCache - will check the cache for not expired PKS if not found will download it. Otherwise do nothing.
	// This feature to be used as preliminary download feature
	DownloadPKSinCache(identityProvider string)

	// Get the issuer value from the OpenIDProvider stored
	GetIssuerVal(provider string) (string, error)
}

type service struct {
	keyset    ivmanto.PublicKeySetRepository
	providers ivmanto.OIDProviderRepository
}

// Initiating OpenID Providers
func (s *service) InitOIDProviders() {
	var err error
	var ips = []string{"google", "apple"}

	for _, ip := range ips {
		if err = s.newPKS(ip); err != nil {
			continue
		}
	}
}

// NewPKS creates new Public Key Set for the ip (Identity Provider)
func (s *service) newPKS(ip string) error {

	var oidc ivmanto.OpenIDConfiguration
	var prvn ivmanto.ProviderName
	var oidp ivmanto.OIDProvider
	var pks *ivmanto.PublicKeySet
	var err error

	prvn = ivmanto.ProviderName(ip)
	pks = ivmanto.NewPublicKeySet(ip)

	switch ip {
	case "google":
		// getting Google's OpenID Configuration
		oidc, err = getGooglesOIC(pks)
		if err != nil {
			return err
		}
		oidp = ivmanto.OIDProvider{
			ProviderName: prvn,
			Oidc:         oidc,
		}
		_ = s.providers.Store(&oidp)

		// fullfiling PKS
		pks.URL, err = url.Parse(oidc.JWKSURI)
		if err != nil {
			return err
		}
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
	default:
		// TODO: Add more Identity providers below
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

	return n, e, nil
}

// DownloadPKSinCache - will check the cache for not expired PKS if not found will download it. Otherwise do nothing.
// This feature to be used as preliminary download feature
func (s *service) DownloadPKSinCache(identityProvider string) {

	// Check the cache for PKS
	pks, err := s.keyset.Find(identityProvider)
	if err != nil && err.Error() == "key not found" {
		err = nil
		// Not found - download it again from the providers url
		err = s.newPKS(identityProvider)
		if err != nil {
			return
		}
	}

	// Found in cache in the searches above - check if not expired
	if pks.Expires < time.Now().Unix()+int64(time.Second*60) {
		// has expired or will expire in the next minute - try to download it again
		err = s.newPKS(identityProvider)
		if err != nil {
			// error when downloading it
			return
		}
	}
}

// GetPKSCache finds the PKS and returns it from the cache. If not found, calls NewPKS
//  to download the keys from the URL
func (s *service) GetPKSCache(identityProvider string) (*ivmanto.PublicKeySet, error) {

	// Get the pks from the cache
	pks, err := s.keyset.Find(identityProvider)
	if err != nil && err.Error() == "key not found" {
		err = nil
		// Not found - download it again from the providers url
		err = s.newPKS(identityProvider)
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
		err = s.newPKS("google")
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

// Get the issuer value from the OpenIDProvider stored
func (s *service) GetIssuerVal(provider string) (string, error) {

	var prv *ivmanto.OIDProvider
	var err error

	prv, err = s.providers.Find(ivmanto.ProviderName(provider))
	if err != nil {
		return "", err
	}
	return prv.Oidc.Issuer, nil
}

// NewService creates a authenticating service with necessary dependencies.
func NewService(pksr ivmanto.PublicKeySetRepository, oidpr ivmanto.OIDProviderRepository) Service {
	return &service{
		keyset:    pksr,
		providers: oidpr,
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

	// For Cache-Control expire time calculation
	var exp int64

	cc := resp.Header.Get("Cache-Control")
	ccp := strings.Split(cc, ",")
	for _, p := range ccp {
		if strings.HasPrefix(p, "max-age=") {
			mapr := strings.Split(p, "=")
			ma, err := strconv.ParseInt(mapr[1], 10, 64)
			if err != nil {
				// TODO: logging ("WARNING: Cache-Control max-age value is not an int.")
				ma = 0
			}
			exp += ma
		}
	}
	exp += time.Now().Unix()

	return jwksb, exp, nil
}

// getGooglesOIC - calls the URL https://accounts.google.com/.well-known/openid-configuration
// and extracts the jwks_uri attribute to be further used here
func getGooglesOIC(pks *ivmanto.PublicKeySet) (config ivmanto.OpenIDConfiguration, err error) {

	var oidconfig ivmanto.OpenIDConfiguration

	resp, err := pks.HTTPClient.Get("https://accounts.google.com/.well-known/openid-configuration")
	if err != nil {
		return oidconfig, ErrExtEndpointResponse
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return oidconfig, ErrExtEndpointResponse
	}

	if resp.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(resp.Body).Decode(&oidconfig); err != nil {
			return oidconfig, ErrExtEndpointResponse
		}
	}

	return oidconfig, nil
}

// ErrInvalidArgument is returned when one or more arguments are invalid.
var ErrInvalidArgument = errors.New("invalid argument")

// ErrExtEndpointResponse returned when a call to external endpoint failed to return response
var ErrExtEndpointResponse = errors.New("error getting external endpoint response")
