package server

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/dasiyes/ivmauth/svc/authenticating"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
	"github.com/dasiyes/ivmsesman"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

// processAuthCode will handle the requests sent for authorize as initation of the AuthCode fllow with PKCE extension
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

	var err error
	_ = level.Debug(h.logger).Log("requestURI", r.RequestURI)

	r.URL.RawQuery, err = url.QueryUnescape(r.URL.RawQuery)
	if err != nil {
		fmt.Printf("error unescaping URL query: %q\n", err.Error())
	}

	q := r.URL.Query()

	_ = level.Debug(h.logger).Log("response_type", q.Get("response_type"))
	_ = level.Debug(h.logger).Log("client_id", q.Get("client_id"))
	_ = level.Debug(h.logger).Log("redirect_uri", q.Get("redirect_uri"))
	_ = level.Debug(h.logger).Log("scope", q.Get("scope"))
	_ = level.Debug(h.logger).Log("state", q.Get("state"))
	_ = level.Debug(h.logger).Log("code_challenge", q.Get("code_challenge"))
	_ = level.Debug(h.logger).Log("code_challenge_method", q.Get("code_challenge_method"))

	var sid = q.Get("state")
	var coch = q.Get("code_challenge")
	var mth = q.Get("code_challenge_method")

	// save the code_challenge along with the code_challenge_method in the Session-Store (firestore)
	err = h.sm.SaveCodeChallengeAndMethod(sid, coch, mth)
	if err != nil {
		w.Header().Set("Connection", "close")
		_ = level.Error(h.logger).Log("processAuthCode", err.Error())
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// TODO [dev]: Response in the format:
	// https://example-app.com/cb?code=AUTH_CODE_HERE&state=1234zyx

	http.Redirect(w, r, "https://example-app.com/cb?code=AUTH_CODE_HERE&state=1234zyx", http.StatusSeeOther)
}
