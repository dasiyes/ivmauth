// The package pksrefreshing will holds the methods to manage and serve the OpenID Providers' public keys
package pksrefreshing

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmconfig/src/pkg/config"
	"github.com/golang-jwt/jwt"
)

// Service is the interface that provides the service's methods.
type Service interface {

	// InitOIDProviders
	InitOIDProviders(oidps []string) (errs []error)

	// GetRSAPublicKey gets the jwks, finds the JWK by kid and returns it as rsa.PublicKey format
	GetRSAPublicKey(identityProvider string, kid string) (*big.Int, int, error)

	// GetPKSCache - finds and returns PKS from the cache, if available
	GetPKSCache(identityProvider string) (*core.PublicKeySet, error)

	// DEPRICATED - replaced by the InitOIDProviders
	// DownloadPKSinCache - will check the cache for not expired PKS if not found will download it. Otherwise do nothing.
	// This feature to be used as preliminary download feature
	// DownloadPKSinCache(identityProvider string) error

	// Get the issuer value from the OpenIDProvider stored
	GetIssuerVal(provider string) (string, error)

	// PKSRotetor will take care for rotating PKS for OIDProvider Ivmanto
	PKSRotator() error
}

type service struct {
	keyset    core.PublicKeySetRepository
	providers core.OIDProviderRepository
	cfg       *config.OpenIDConfiguration
}

// Initiating OpenID Providers
func (s *service) InitOIDProviders(oidps []string) []error {
	var err error
	var errs []error

	for _, ip := range oidps {
		if err = s.newPKS(ip); err != nil {
			errs = append(errs, fmt.Errorf("while init provider [%s], raised [%#v]", ip, err))
			continue
		}
	}
	return errs
}

// NewPKS creates new Public Key Set for the ip (Identity Provider)
func (s *service) newPKS(ip string) error {

	var oidc *config.OpenIDConfiguration
	var prvn core.ProviderName
	var oidp *core.OIDProvider
	var pks *core.PublicKeySet
	var err error

	prvn = core.ProviderName(ip)
	pks = core.NewPublicKeySet(ip)

	switch ip {
	case "ivmanto":
		// [x] Implement initial load of Ivmanto's OID Provider configuration from the config file. Update the configuration into the firestore DB.
		// cfg passed to pkr service will hold defacto Ivmanto's configuration loaded from the config file.
		oidp = core.NewOIDProvider(prvn)
		oidp.Oidc = s.cfg

		if err = s.providers.Store(oidp); err != nil {
			return err
		}

		// fullfilling PKS
		// pks.URL, err = url.Parse(oidp.Oidc.JwksURI)
		pks.URL = oidp.Oidc.JwksURI
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

		// [!] Review the code below again! As of now the process does not require it!

		err = pks.AddJWK(jwt.SigningMethodRS256)
		if err != nil {
			return err
		}

		if err := s.keyset.Store(pks); err != nil {
			return err
		}

	case "google":
		// getting Google's OpenID Configuration
		oidc, err = getGooglesOIC(pks)
		if err != nil {
			return err
		}
		oidp = core.NewOIDProvider(prvn)
		oidp.Oidc = oidc

		_ = s.providers.Store(oidp)

		// fullfiling PKS
		// pks.URL, err = url.Parse(oidc.JwksURI)
		pks.URL = oidp.Oidc.JwksURI
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

// DEPRICATED - replaced by the InitOIDProviders
// DownloadPKSinCache - will check the cache for not expired PKS if not found will download it. Otherwise do nothing.
// This feature to be used as preliminary download feature
// func (s *service) DownloadPKSinCache(identityProvider string) error {
//
// 	// Check the cache for PKS
// 	pks, err := s.keyset.Find(identityProvider)
// 	if err != nil && err.Error() == "key not found" {
// 		err = nil
// 		if identityProvider == "ivmanto" {
// 			err = s.PKSRotator()
// 			if err != nil {
// 				return fmt.Errorf("error while rotating PKS %#v", err)
// 			}
// 		} else {
// 			// Not found - download it again from the providers url
// 			err = s.newPKS(identityProvider)
// 			if err != nil {
// 				return fmt.Errorf("error %#v while newPKS for provider %s ", err, identityProvider)
// 			}
//
// 			// Found in cache in the searches above - check if not expired
// 			// This is valid only for third party identityProvider. Ivmanto's pks will
// 			// be managed by PKSRotator.
// 			if pks.Expires < time.Now().Unix()+int64(time.Second*60) {
// 				// has expired or will expire in the next minute - try to download it again
// 				err = s.newPKS(identityProvider)
// 				if err != nil {
// 					// error when downloading it
// 					return fmt.Errorf("error %#v when newPKS because expired, for provider %s ", err, identityProvider)
// 				}
// 			}
// 		}
// 	}
//
// 	return nil
// }

// GetPKSCache finds the PKS and returns it from the cache. If not found, calls NewPKS
//  to download the keys from the URL
func (s *service) GetPKSCache(identityProvider string) (*core.PublicKeySet, error) {

	// Get the pks from the cache
	pks, err := s.keyset.Find(identityProvider)
	if err != nil && err.Error() == "key not found" {
		err = nil
		// Not found - download it again from the providers url
		err = s.newPKS(identityProvider)
		if err != nil {
			// error when downloading it - return empty pks and error
			return nil, fmt.Errorf("Error while creating a new PKS: %#v for IdentyProvider: %s", err, identityProvider)
		}
		// Try again to find it in cache - once the download has been called
		pks, err = s.keyset.Find(identityProvider)
		if err != nil {
			// Not found again - return empty pks and error
			return nil, fmt.Errorf("Error while Find (again) PKS in cache for IdentyProvider: %s", identityProvider)
		}
	} else if err != nil {
		return nil, fmt.Errorf("Error %#v, searching PKS in cache for IdentyProvider: %s", err, identityProvider)
	}
	// Found in cache in the searches above - check if not expired
	// if pks.Expires < time.Now().Unix()+int64(time.Second*30) {
	// 	// has expired - try to download it again
	// 	err = s.newPKS(identityProvider)
	// 	if err != nil {
	// 		// error when downloading it - return empty pks and error
	// 		return &core.PublicKeySet{}, errors.New("Error while creating a new PKS: " + err.Error())
	// 	}
	// 	// Try to find it again after the new download
	// 	pks, err = s.keyset.Find(identityProvider)
	// 	if err != nil {
	// 		// Not found again - return empty pks and error
	// 		return &core.PublicKeySet{}, err
	// 	}
	// }

	return pks, nil
}

// Get the issuer value from the OpenIDProvider stored
func (s *service) GetIssuerVal(provider string) (string, error) {

	var prv *core.OIDProvider
	var err error

	prv, err = s.providers.Find(core.ProviderName(provider))
	if err != nil {
		return "", err
	}
	return prv.Oidc.Issuer, nil
}

// PKSRotetor will take care for rotating PKS for OIDProvider Ivmanto
//
// [ ] 1. We request/create new key material.
// [ ] 2. Then we publish the new validation key in addition to the current one.
// [ ] 3. All clients and APIs now have a chance to learn about the new key the next time they update their local copy of the discovery document.
// [ ] 4. After a certain amount of time (e.g. 24h) all clients and APIs should now accept both the old and the new key material.
// [ ] 5. Keep the old key material around for as long as you like, maybe you have long-lived tokens that need validation.
// [ ] 6. Retire the old key material when it is not used anymore.
// [ ] 7. All clients and APIs will “forget” the old key next time they update their local copy of the discovery document.
// This requires that clients and APIs use the discovery document, and also have a feature to periodically refresh their configuration.
func (s *service) PKSRotator() error {

	// TODO [dev]: add time-based code that will TRIGGER the key rotation on regular (ie. 1 month) base.

	// TODO [dev]: generate Public key from the private key below.
	// TODO [dev]: implement kid ?!
	key, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return err
	}
	_ = key

	return nil
}

// NewService creates a authenticating service with necessary dependencies.
func NewService(
	pksr core.PublicKeySetRepository,
	oidpr core.OIDProviderRepository,
	cfg *config.OpenIDConfiguration) Service {

	return &service{
		keyset:    pksr,
		providers: oidpr,
		cfg:       cfg,
	}
}

// downloadJWKS - download jwks from the URL for the respective Identity provider
func downloadJWKS(pks *core.PublicKeySet) ([]byte, int64, error) {

	// resp, err := pks.HTTPClient.Get(pks.URL.String())
	resp, err := pks.HTTPClient.Get(pks.URL)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, 0, errors.New("error while getting JWKS from identity provider url")
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
				fmt.Printf("error converting max-age value to int. Default value of 3600 seconds will be used. error: %#v", err)
				ma = 3600
			}
			exp += ma
		}
	}
	exp += time.Now().Unix()

	return jwksb, exp, nil
}

// getGooglesOIC - calls the URL https://accounts.google.com/.well-known/openid-configuration
// and extracts the jwks_uri attribute to be further used here
func getGooglesOIC(pks *core.PublicKeySet) (cfg *config.OpenIDConfiguration, err error) {

	var oidconfig config.OpenIDConfiguration

	resp, err := pks.HTTPClient.Get("https://accounts.google.com/.well-known/openid-configuration")
	if err != nil {
		return &oidconfig, ErrExtEndpointResponse
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return &oidconfig, ErrExtEndpointResponse
	}

	if resp.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(resp.Body).Decode(&oidconfig); err != nil {
			return &oidconfig, ErrExtEndpointResponse
		}
	}

	return &oidconfig, nil
}

// ErrInvalidArgument is returned when one or more arguments are invalid.
var ErrInvalidArgument = errors.New("invalid argument")

// ErrExtEndpointResponse returned when a call to external endpoint failed to return response
var ErrExtEndpointResponse = errors.New("error getting external endpoint response")
