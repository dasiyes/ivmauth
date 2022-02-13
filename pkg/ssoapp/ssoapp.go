package ssoapp

import (
	"html/template"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmconfig/src/pkg/config"
	kitlog "github.com/go-kit/log"
)

type IvmSSO struct {
	templateCache map[string]*template.Template
	logger        *kitlog.Logger
	cfg           config.IvmCfg
	Users         core.UserRepository
}

// NewIvmSSO creates a new instance of Ivmanto's Single SignOn application
func NewIvmSSO(
	tc map[string]*template.Template,
	logger *kitlog.Logger,
	cfg config.IvmCfg,
	u core.UserRepository) *IvmSSO {

	a := IvmSSO{
		templateCache: tc,
		logger:        logger,
		cfg:           cfg,
		Users:         u,
	}

	return &a
}
