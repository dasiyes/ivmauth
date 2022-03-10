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
	RegisterUser(names, email, password, provider, state string, subCode core.SubCode) error

	// ActivateUser will activate newly registered users
	ActivateUser(userId, subcode, state string) error

	//
}

type service struct {
	clients core.ClientRepository
	users   core.UserRepository
	config  *config.IvmCfg
}

func (s *service) RegisterUser(names, email, password, provider, state string, subCode core.SubCode) error {

	var mpl = 8
	var psw []byte
	var errgp error

	if provider == "ivmanto" {
		if !tools.PswCheck(password, mpl) {
			return fmt.Errorf("the suplied password did not pass the checks")
		}
		psw, errgp = bcrypt.GenerateFromPassword([]byte(password), 12)
		if errgp != nil {
			return fmt.Errorf("error while bcrypting the password: %#v", errgp)
		}
	}

	u := &core.User{
		UserID:       core.UserID(email),
		Name:         names,
		SubCode:      subCode,
		Password:     psw,
		OIDCProvider: provider,
		Status:       core.EntryStatusDraft,
		InitState:    state,
	}

	err := s.users.Store(u)
	if err != nil {
		return fmt.Errorf("while saving the user with code %s, error raised: %v", subCode, err)
	}

	return nil
}

func (s *service) ActivateUser(userId, subcode, state string) error {

	err := s.users.ActivateUserAccount(userId, subcode, state)
	if err != nil {
		return fmt.Errorf("error while activating user %s, error: %s", userId, err)
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
