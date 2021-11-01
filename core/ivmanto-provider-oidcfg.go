package core

import "github.com/dasiyes/ivmconfig/src/pkg/config"

// LoadIvmantoOIDCfg will read the configuration file and load the attributes for Ivmanto's OpenID Connect configuration as instance of *core.OpenIDConfiguration
func LoadIvmantoOIDCfg(cfg *config.IvmCfg) (*config.OpenIDConfiguration, error) {
	var ivmOIDC = config.OpenIDConfiguration{}

	return &ivmOIDC, nil
}
