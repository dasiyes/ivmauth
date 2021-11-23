package pksrefreshing

import (
	"errors"
	"fmt"
	"testing"
)

var svc = NewService(nil, nil, nil, nil)

func TestInitOIDProviders(t *testing.T) {
	var p = []string{"p1", "p2"}
	t.Run("test empty array of providers", func(t *testing.T) {
		errs := svc.InitOIDProviders([]string{})
		errcf := errors.New("empty array of OpenID providers. Check the configuration file")
		if errs[0].Error() != errcf.Error() {
			fmt.Printf("expected %q : got %q", errcf, errs[0])
			t.Fail()
		}
	})

	t.Run("test two unknown providers array", func(t *testing.T) {
		errs := svc.InitOIDProviders(p)
		if len(errs) != 2 {
			fmt.Printf("length of errors %d", len(errs))
			t.Fail()
		}
	})
}

func TestNewPKS(t *testing.T) {

}
