// Package config is package specific to ivmauth service to handle all configuration options for the service
package config

import (
	"io/ioutil"
	"os"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"gopkg.in/yaml.v2"
	"ivmanto.dev/ivmauth/ivmanto"
)

const (
	// DefaultPort where the server will lsiten to in case no else value is set
	DefaultPort = "8080"

	// DefaultGCP is the default GCP projectID to be used
	DefaultGCP = "ivmauth"

	// Dev environment
	Dev ivmEnvT = "dev"

	// Staging environment
	Staging ivmEnvT = "staging"

	// Prod environment
	Prod ivmEnvT = "prod"
)

// IvmCfg Ivmauth service configuration
type IvmCfg interface {
	// Return new service configuration composed by the requested parameters
	LoadCfg(env *string, logger log.Logger) error

	// GetHTTPAddr returns the config value for the http server
	GetHTTPAddr() string

	// GCPPID return the projectID for the GCP
	GCPPID() string

	// Environment returns the environment configured in the system
	Environment() ivmEnvT

	// GetATC will return config options for the creting access token service
	GetATC() *ivmanto.ATCfg
}

// IvmCfg will hold the config option to be used across the service
type ivmCfg struct {
	Env      ivmEnv
	Server   ivmServer
	CloudEnv ivmCloud `yaml:"cloud_env"`
	Atc      ivmanto.ATCfg
}

type ivmEnv struct {
	EnvType ivmEnvT `yaml:"env_type"`
	cif     string
	csc     string
}

type ivmEnvT string

type ivmServer struct {
	Host string `yaml:"host,omitempty"`

	// @required
	Port string
}

type ivmCloud struct {
	ProjectID string `yaml:"project_id"`
}

// Init vreates a new empty instance of ivmCfg object
func Init() IvmCfg {
	return &ivmCfg{}
}

// LoadCfg will load the configuration from the file name in cf.
// The yaml file may contains environment variables assigned to the config attributes with ${env_var_name} notation.
func (c *ivmCfg) LoadCfg(rtaenv *string, lg log.Logger) error {

	var err error
	var cf string = "config-" + *rtaenv + ".yaml"

	if err = c.init(cf); err != nil {
		_ = level.Debug(lg).Log("load-config-error", err)
		return err
	}

	if string(c.Env.EnvType) != *rtaenv {
		_ = level.Debug(lg).Log("WARNNING", "Missmatch environment setup. Runtime argument takes over")
		c.Env.EnvType = ivmEnvT(*rtaenv)
	}

	return nil
}

// init will initially load the config from the cf file
//  - expand environment variables
func (c *ivmCfg) init(cf string) error {

	confContent, err := ioutil.ReadFile(cf)
	if err != nil {
		return err
	}

	confContent = []byte(os.ExpandEnv(string(confContent)))

	if err := yaml.Unmarshal(confContent, c); err != nil {
		return err
	}

	return nil
}

// GetHTTPAddr compose the http server address
func (c *ivmCfg) GetHTTPAddr() string {
	return c.Server.Host + ":" + c.Server.Port
}

// GCPPID willreturn the GCP cloud projet ID
func (c *ivmCfg) GCPPID() string {
	return c.CloudEnv.ProjectID
}

// Env will return the environment configured in the system.
func (c *ivmCfg) Environment() ivmEnvT {
	return c.Env.EnvType
}

// GetATC will return config options for the creting access token service
func (c *ivmCfg) GetATC() *ivmanto.ATCfg {

	var validity int = c.Atc.Validity
	var realm string = c.Atc.Realm
	var alg string = c.Atc.Alg
	var issuer string

	if validity == 0 {
		validity = 3600
	}

	if realm == "" {
		realm = "ivmanto.com"
	}

	if alg == "" {
		alg = "RS256"
	}

	if issuer == "" {
		issuer = "https://accounts.ivmanto.com"
	}

	return &ivmanto.ATCfg{
		Validity:  validity,
		Realm:     realm,
		Alg:       alg,
		IssuerVal: issuer,
	}
}
