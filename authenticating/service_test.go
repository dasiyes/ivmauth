package authenticating

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dvsekhvalnov/jose2go/base64url"
	"ivmanto.dev/ivmauth/ivmanto"
)

// TestAuthenticateClientAH - testing client authentication over Basic Authorization Header
func TestAuthenticateClientAH(t *testing.T) {

	var clients mockClientRepository
	s := NewService(nil, &clients)

	// prep the client credentials for Auth Header
	bc := "Basic " + base64url.Encode([]byte("xxx.apps.ivmanto.dev:ivmanto-2021"))

	// Store the same client in the clients repository
	client2 := ivmanto.NewClient("xxx.apps.ivmanto.dev", ivmanto.Active)
	client2.ClientSecret = "ivmanto-2021"
	if err := clients.Store(client2); err != nil {
		t.Logf("error saving test client2: %#v;\n", err)
	}

	// create a new request to use for the function test
	req := httptest.NewRequest("POST", "http://localhost:8080/v1/auth", nil)
	req.Header.Set("Authorization", bc)

	err := s.AuthenticateClient(req)
	if err != nil {
		t.Errorf("AuthenticateClient returned error: %#v;\n", err)
	}
}

// TestAuthenticateClientWFUE - test client authentication over body "application/x-www-form-urlencoded"
func TestAuthenticateClientWFUE(t *testing.T) {

	var clients mockClientRepository
	s := NewService(nil, &clients)

	// prep the client credentials for Auth Header
	formdata := "grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&client_id=xxx.apps.ivmanto.dev&client_secret=ivmanto-2021"

	// Store the same client in the clients repository
	client2 := ivmanto.NewClient("xxx.apps.ivmanto.dev", ivmanto.Active)
	client2.ClientSecret = "ivmanto-2021"
	if err := clients.Store(client2); err != nil {
		t.Logf("error saving test client2: %#v;\n", err)
	}

	req := httptest.NewRequest("POST", "https://localhost:8080/v1/auth", strings.NewReader(formdata))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	err := s.AuthenticateClient(req)
	if err != nil {
		t.Errorf("AuthenticateClient returned error: %#v;\n", err)
	}
}

type mockClientRepository struct {
	client *ivmanto.Client
}

func (r *mockClientRepository) Store(c *ivmanto.Client) error {
	r.client = c
	return nil
}

func (r *mockClientRepository) Find(id ivmanto.ClientID) (*ivmanto.Client, error) {
	if r.client != nil {
		return r.client, nil
	}
	return nil, errors.New("unknown client")
}

func (r *mockClientRepository) FindAll() []*ivmanto.Client {
	return []*ivmanto.Client{r.client}
}
