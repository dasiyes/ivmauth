package ssoapp

import (
	"html/template"

	"github.com/dasiyes/ivmauth/core"
	kitlog "github.com/go-kit/log"
)

type IvmSSO struct {
	templateCache map[string]*template.Template
	logger        *kitlog.Logger
	Users         core.UserRepository
}

// NewIvmSSO creates a new instance of Ivmanto's Single SignOn application
func NewIvmSSO(
	tc map[string]*template.Template,
	logger *kitlog.Logger,
	u core.UserRepository) *IvmSSO {

	a := IvmSSO{
		templateCache: tc,
		logger:        logger,
		Users:         u,
	}

	return &a
}
