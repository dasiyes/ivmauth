package authenticating

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dvsekhvalnov/jose2go/base64url"
)

// TODO:	AuthenticateClient
// TestAuthenticateClientAH - testing client authentication over Basic Authorization Header
func TestAuthenticateClientAH(t *testing.T) {

	var clients mockClientRepository
	s := NewService(nil, &clients, nil, nil)

	// prep the client credentials for Auth Header
	bc := "Basic " + base64url.Encode([]byte("xxx.apps.ivmanto.dev:ivmanto-2021"))

	// Store the same client in the clients repository
	client2 := core.NewClient("xxx.apps.ivmanto.dev", core.Active)
	client2.ClientSecret = "ivmanto-2021"
	if err := clients.Store(client2); err != nil {
		t.Logf("error saving test client2: %#v;\n", err)
	}

	// create a new request to use for the function test
	req := httptest.NewRequest("POST", "http://localhost:8080/v1/auth", nil)
	req.Header.Set("Authorization", bc)
	req.Header.Set("Content-Type", "application/json")

	rc, err := s.AuthenticateClient(req)
	if err != nil {
		t.Errorf("AuthenticateClient returned error: %#v;\n", err)
	}
	if rc.ClientID != "xxx.apps.ivmanto.dev" {
		t.Errorf("AuthenticateClient returned error. ClientID does not match. Returned value %#v;\n %#v;\n", rc.ClientID, "xxx.apps.ivmanto.dev")
	}
}

// TestAuthenticateClientWFUE - test client authentication over body "application/x-www-form-urlencoded"
func TestAuthenticateClientWFUE(t *testing.T) {

	var clients mockClientRepository
	s := NewService(nil, &clients, nil, nil)

	// prep the client credentials for Auth Header
	formdata := "grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&client_id=xxx.apps.ivmanto.dev&client_secret=ivmanto-2021"

	// Store the same client in the clients repository
	client2 := core.NewClient("xxx.apps.ivmanto.dev", core.Active)
	client2.ClientSecret = "ivmanto-2021"
	if err := clients.Store(client2); err != nil {
		t.Logf("error saving test client2: %#v;\n", err)
	}

	req := httptest.NewRequest("POST", "https://localhost:8080/v1/auth", strings.NewReader(formdata))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rc, err := s.AuthenticateClient(req)
	if err != nil {
		t.Errorf("AuthenticateClient returned error: %#v;\n", err)
	}
	if rc.ClientID != "xxx.apps.ivmanto.dev" {
		t.Errorf("AuthenticateClient returned error. ClientID does not match. Returned value %#v;\n %#v;\n", rc.ClientID, "xxx.apps.ivmanto.dev")
	}
}

type mockClientRepository struct {
	client *core.Client
}

func (r *mockClientRepository) Store(c *core.Client) error {
	r.client = c
	return nil
}

func (r *mockClientRepository) Find(id core.ClientID) (*core.Client, error) {
	if r.client != nil {
		return r.client, nil
	}
	return nil, errors.New("unknown client")
}

func (r *mockClientRepository) FindAll() []*core.Client {
	return []*core.Client{r.client}
}

// TODO: RegisterNewRequest

// TODO: Validate

// TODO: GetRequestBody

// TODO: IssueAccessToken

// TODO: CheckUserRegistration
// TestCheckUserRegistration - checking if a user is alredy registred and if not create a new one
func TestCheckUserRegistration(t *testing.T) {
	var users mockUserRepository
	s := NewService(nil, nil, &users, nil)

	oid := core.IDToken{
		Email: "nikolay.tonev55@gmail.com",
	}
	// TODO: find the way to test if the function works well...
	s.CheckUserRegistration(&oid)
}

type mockUserRepository struct {
	user *core.User
}

func (r *mockUserRepository) Store(u *core.User) error {
	r.user = u
	return nil
}

func (r *mockUserRepository) Find(id core.UserID) (*core.User, error) {
	if r.user != nil {
		return r.user, nil
	}
	return nil, errors.New("unknown client")
}

func (r *mockUserRepository) FindAll() []*core.User {
	return []*core.User{}
}
