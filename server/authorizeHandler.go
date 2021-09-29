package server

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/dasiyes/ivmsesman"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/pksrefreshing"
)

type authorizeHandler struct {
	aus    authenticating.Service
	pks    pksrefreshing.Service
	logger kitlog.Logger
	sm     *ivmsesman.Sesman
}

func (h *authorizeHandler) router() chi.Router {

	r := chi.NewRouter()
	r.Method("GET", "/metrics", promhttp.Handler())

	r.Route("/", func(r chi.Router) {
		r.Get("/", h.processAuthCode)
	})

	return r
}

func (h *authorizeHandler) processAuthCode(w http.ResponseWriter, r *http.Request) {

	// Sample:
	//
	//https://authorization-server.com/authorize?
	//response_type=code
	//&client_id=H-hICOjJs8_4pxiyqud9jvxZ
	//&redirect_uri=https://www.oauth.com/playground/authorization-code-with-pkce.html
	//&scope=photo+offline_access
	//&state=ZwUAXBT9cf0btwOR
	//&code_challenge=U4wChzuCcE215Yha-Qc7ZoBc4u1rkeFHJCoQUUPcD0E
	//&code_challenge_method=S256

	u, err := url.Parse(r.RequestURI)
	if err != nil {
		_ = level.Error(h.logger).Log("ParseRequestUri-Error", err.Error())
		// TODO [dev]: code to return unauthorized resonse

	}
	q := u.Query()
	fmt.Println(q["response_type"])
	fmt.Println(q.Get("client_id"))
	fmt.Println(q["redirect_uri"])
	fmt.Println(q["scope"])
	fmt.Println(q["state"])
	fmt.Println(q["code_challenge"])
	fmt.Println(q["code_challenge_method"])
	w.Write([]byte(`authorize--->`))
}
