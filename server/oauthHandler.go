package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dasiyes/ivmapi/pkg/tools"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dasiyes/ivmauth/pkg/forms"
	"github.com/dasiyes/ivmauth/pkg/ssoapp"
)

type oauthHandler struct {
	server *Server
	logger kitlog.Logger
}

func (h *oauthHandler) router() chi.Router {

	r := chi.NewRouter()
	r.Method("GET", "/metrics", promhttp.Handler())

	r.Route("/", func(r chi.Router) {
		r.Get("/authorize", h.processAuthCode)
		r.Post("/login", h.authLogin)
		r.Route("/ui", func(r chi.Router) {
			r.Get("/login", h.userLoginForm)
		})
	})

	r.Method("GET", "/docs", http.StripPrefix("/auth/v1/docs", http.FileServer(http.Dir("authenticating/docs"))))

	return r
}

// [WIP] processAuthCode will handle the requests sent for authorize as initation of the AuthCode fllow with PKCE extension
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
		h.server.responseBadRequest(w, "processAuthCode", errors.New("missing mandatory code challenge or method"))
	}

	var code = tools.GenerateAuthCode(sid, coch, mth)
	if code == "" {
		h.server.responseUnauth(w, "processAuthCode", errors.New("error while generating the auth code"))
		return
	}

	// save the code_challenge along with the code_challenge_method and the code itself in the Session-Store (firestore)
	err = h.server.Sm.SaveCodeChallengeAndMethod(sid, coch, mth, code)
	if err != nil {
		h.server.responseUnauth(w, "processAuthCode", err)
		return
	}

	// GetAPIGWSvcURL will return the host for the api gateway service
	var api_gw_host = h.server.Config.GetAPIGWSvcURL()
	var redirectURL = fmt.Sprintf("https://%s/oauth/ui/login?t=%s", api_gw_host, sid)

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// authLogin - validate user's input credentials
func (h *oauthHandler) authLogin(w http.ResponseWriter, r *http.Request) {

	headerContentTtype := r.Header.Get("Content-Type")
	if headerContentTtype != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		h.server.responseBadRequest(w, "authLogin", fmt.Errorf("unsupported media type %s", headerContentTtype))
		return
	}

	r.ParseForm()

	var email = r.FormValue("email")
	var password = r.FormValue("password")
	var state = r.FormValue("csrf_token")
	var cid = r.FormValue("client_id")

	valid, err := h.server.Auth.ValidateUsersCredentials(email, password)
	if err != nil {
		//h.server.responseUnauth(w, "authLogin", err)
		//return
		fmt.Printf("err: %s\n", err.Error())
	}
	_ = valid

	val := true

	if val {
		// the redirect url should be in the format:
		// https://ivmanto.dev/pg/cb?code=AUTH_CODE_HERE&state=THE_STATE_FROM_THE_FORM
		// TODO [dev]: WHEN credentials are verified and user is authenticated - redirect to the client with all paramrs from method "processAuthCode"

		call_back_url, err := h.server.Auth.GetClientsRedirectURI(cid)
		if err != nil {
			_ = level.Error(h.logger).Log("error-get-redirect-uri", err.Error())
		}

		if call_back_url == "" {
			// GetAPIGWSvcURL will return the host for the api gateway service
			api_gw_host := h.server.Config.GetAPIGWSvcURL()
			call_back_url = fmt.Sprintf("https://%s/pg/cb", api_gw_host)
		}

		// TODO [dev]: GET it from the session state
		var ac = h.server.Sm.GetAuthCode(state)
		var redirectURL = fmt.Sprintf("%s?code=%s&state=%s", call_back_url, ac, state)

		fmt.Printf("redirect URL: %s\n", redirectURL)

		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	h.server.responseUnauth(w, "authLogin", fmt.Errorf("unauthorized user %s", email))
}

// userLoginForm will handle the UI for users Login Form
func (h *oauthHandler) userLoginForm(w http.ResponseWriter, r *http.Request) {
	// fmt.Fprintln(w, "display the Login Form")

	var state = r.URL.Query().Get("t")
	var cid string

	cc, err := r.Cookie("c")
	if err != nil {
		_ = level.Error(h.logger).Log("error-get-client-id", err.Error())
		cid = ""
	} else {
		cid = cc.Value
	}

	var td = ssoapp.TemplateData{
		CSRFToken: state,
		Form:      forms.New(nil),
		ClientID:  cid,
	}
	h.server.IvmSSO.Render(w, r, "login.page.tmpl", &td)

}
