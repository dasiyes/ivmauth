package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"text/template"

	"github.com/dasiyes/ivmapi/pkg/config"
	"github.com/dasiyes/ivmapi/pkg/tools"
	"github.com/dasiyes/ivmauth/svc/authenticating"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
	"github.com/dasiyes/ivmsesman"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type oauthHandler struct {
	aus    authenticating.Service
	pks    pksrefreshing.Service
	logger kitlog.Logger
	sm     *ivmsesman.Sesman
	cfg    config.IvmCfg
}

func (h *oauthHandler) router() chi.Router {

	r := chi.NewRouter()
	r.Method("GET", "/metrics", promhttp.Handler())

	r.Route("/", func(r chi.Router) {
		r.Get("/authorize", h.processAuthCode)
		r.Get("/login", h.serveLoginPage)
	})

	return r
}

// processAuthCode will handle the requests sent for authorize as initation of the AuthCode fllow with PKCE extension
func (h *oauthHandler) processAuthCode(w http.ResponseWriter, r *http.Request) {

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

	var sid = strings.TrimSpace(q.Get("state"))
	var coch = strings.TrimSpace(q.Get("code_challenge"))
	var mth = strings.TrimSpace(q.Get("code_challenge_method"))

	if coch == "" || mth == "" {
		h.responseBadRequest(w, "processAuthCode", errors.New("missing mandatory code challenge or method"))
	}

	var code = tools.GenerateAuthCode(sid, coch, mth)
	if code == "" {
		h.responseUnauth(w, "processAuthCode", errors.New("error while generating the auth code"))
		return
	}

	// save the code_challenge along with the code_challenge_method and the code itself in the Session-Store (firestore)
	err = h.sm.SaveCodeChallengeAndMethod(sid, coch, mth, code)
	if err != nil {
		h.responseUnauth(w, "processAuthCode", err)
		return
	}

	// Response in the format:
	// https://example-app.com/cb?code=AUTH_CODE_HERE&state=1234zyx

	// var wa_host = h.cfg.GetWebAppURL()
	var wa_host = h.cfg.GetSvsCfg().Host[0]
	var redirectURL = fmt.Sprintf("https://%s/cb?code=%s&state=%s", wa_host, code, sid)

	_ = redirectURL

	// TODO [dev]: refactor to proper call to a LoginSvc
	h.serveLoginPage(w, r)

	// TODO [dev]: after the LoginSvc return TRUE for successful complete operation of user authentication - redirect to the client below...
	// http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (h *oauthHandler) responseUnauth(w http.ResponseWriter, method string, err error) {
	w.Header().Set("Connection", "close")
	_ = level.Error(h.logger).Log("handler", "oauthHandler", fmt.Sprintf("method-%s", method), err.Error())
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func (h *oauthHandler) responseBadRequest(w http.ResponseWriter, method string, err error) {
	w.Header().Set("Connection", "close")
	_ = level.Error(h.logger).Log("handler", "oauthHandler", fmt.Sprintf("method-%s", method), err.Error())
	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}

func (h *oauthHandler) serveLoginPage(w http.ResponseWriter, r *http.Request) {

	files := []string{
		"./ui/html/login.page.tmpl",
		"./ui/html/base.layout.tmpl",
	}

	ts, err := template.ParseFiles(files...)
	if err != nil {
		h.serverError(w, err)
		return
	}

	// And then execute them. Notice how we are passing in the snippet
	// data (a models.Snippet struct) as the final parameter.
	err = ts.Execute(w, nil)
	if err != nil {
		h.serverError(w, err)
	}
}

// serverError - raise server error
func (h *oauthHandler) serverError(w http.ResponseWriter, err error) {
	trace := fmt.Sprintf("%s\n%s", err.Error(), debug.Stack())

	// log the error
	_ = level.Error(h.logger).Log("debugTrace", trace)

	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
