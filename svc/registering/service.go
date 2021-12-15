package registering

import (
	"fmt"

	"github.com/dasiyes/ivmapi/pkg/tools"
	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmconfig/src/pkg/config"
	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	// RegisterUser will be registering a new user in the ivmauth oauth2 server
	RegisterUser(names, email, password, state string) error
}

type service struct {
	clients core.ClientRepository
	users   core.UserRepository
	config  *config.IvmCfg
}

func (s *service) RegisterUser(names, email, password, state string) error {

	var mpl = 8

	if !tools.PswCheck(password, mpl) {
		return fmt.Errorf("the suplied password did not pass the checks")
	}
	var psw, errgp = bcrypt.GenerateFromPassword([]byte(password), 12)
	if errgp != nil {
		return fmt.Errorf("error while bcrypting the password: %#v", errgp)
	}

	u := &core.User{
		UserID:   core.UserID(email),
		Name:     names,
		SubCode:  core.SubCode(state),
		Password: psw,
	}

	err := s.users.Store(u)
	if err != nil {
		return fmt.Errorf("while saving the user with id %s, error raised: %v", email, err)
	}

	return nil
}

func NewService(clnts core.ClientRepository, usrs core.UserRepository, cfg *config.IvmCfg) Service {

	return &service{
		clients: clnts,
		users:   usrs,
		config:  cfg,
	}
}
