package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/dasiyes/ivmapi/pkg/tools"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dasiyes/ivmauth/core"
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
		r.Post("/token", h.issueToken)
		r.Route("/ui", func(r chi.Router) {
			r.Get("/login", h.userLoginForm)
		})
	})

	r.Method("GET", "/docs", http.StripPrefix("/auth/v1/docs", http.FileServer(http.Dir("authenticating/docs"))))

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
	var ru = strings.TrimSpace(q.Get("redirect_uri"))

	if coch == "" || mth == "" {
		h.server.responseBadRequest(w, "processAuthCode", errors.New("missing mandatory code challenge or method"))
	}

	var code = tools.GenerateAuthCode(sid, coch, mth)
	if code == "" {
		h.server.responseUnauth(w, "processAuthCode", errors.New("error while generating the auth code"))
		return
	}

	// save the code_challenge along with the code_challenge_method and the code itself in the Session-Store (firestore)
	err = h.server.Sm.SaveACA(sid, coch, mth, code, ru)
	if err != nil {
		h.server.responseUnauth(w, "processAuthCode", err)
		return
	}

	// GetAPIGWSvcURL will return the host for the api gateway service
	var api_gw_host = h.server.Config.GetAPIGWSvcURL()
	var redirectURL = fmt.Sprintf("https://%s/oauth/ui/login?t=%s", api_gw_host, sid)

	// redirect the user to user's Login form to capture its credentials
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
	// var cid = r.FormValue("client_id")

	valid, err := h.server.Auth.ValidateUsersCredentials(email, password)
	if err != nil || !valid {
		h.server.responseUnauth(w, "authLogin", err)
		return
		// fmt.Printf("err: %s\n", err.Error())
		// valid = true
	}

	if valid {
		// the redirect url should be in the format:
		// https://ivmanto.dev/pg/cb?code=AUTH_CODE_HERE&state=THE_STATE_FROM_THE_FORM

		// GetAPIGWSvcURL will return the host for the api gateway service
		api_gw_host := h.server.Config.GetAPIGWSvcURL()
		api_gw_cbp := h.server.Config.GetAPIGWSvcCBP()

		call_back_url := fmt.Sprintf("https://%s%s", api_gw_host, api_gw_cbp)

		var ac = h.server.Sm.GetAuthCode(state)
		var redirectURL = fmt.Sprintf("%s?code=%s&state=%s", call_back_url, ac["auth_code"], state)

		// [-] remove after debug
		fmt.Printf("redirect URL: %s\n", redirectURL)

		// redirect to the web application server endpoint dedicated to call-back from /oauth/login
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

// issueToken will return an access token to the post request
func (h *oauthHandler) issueToken(w http.ResponseWriter, r *http.Request) {

	// [x] perform a check for content type header - application/json
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		h.server.responseBadRequest(w, "issueTkon-check-content-type", errors.New("unsupported content type"))
		return
	}

	// Sample content of the POST request body
	// [x] **grant_type=authorization_code** - The grant type for this flow is authorization_code
	// [x] **code=AUTH_CODE_HERE** - This is the code you received in the query string
	// [x] **redirect_uri=REDIRECT_URI** - Must be identical to the redirect URI provided in the original link
	// [x] **client_id=CLIENT_ID** - The client ID you received when you first created the application
	// [x] **client_secret=CLIENT_SECRET** - Since this request is made from server-side code, the secret is included
	// [x] **code_verifier=CODE_VERIFIER** - to support PKCE the code vrifier plain text should be included
	var rb core.AuthRequestBody
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		h.server.responseBadRequest(w, "issueTkon-read-body", err)
		return
	}

	err = json.Unmarshal(b, &rb)
	if err != nil {
		h.server.responseBadRequest(w, "issueTkon-json-body-unmarshal", err)
		return
	}

	switch rb.GrantType {
	case "authorization_code":
		h.handleAuthCodeFllow(&rb, w, r)
		return
	case "refresh_token":
		h.handleRefTokenFllow(&rb, w, r)
		return
	default:
		h.server.responseBadRequest(w, "issueTkon-grant-type", fmt.Errorf("unsupported grant_type fllow [%s]", rb.GrantType))
		return
	}
}

// handleAuthCodeFllow performs the checks and logic for Authorization_code grant_type flow
func (h *oauthHandler) handleAuthCodeFllow(
	rb *core.AuthRequestBody,
	w http.ResponseWriter,
	r *http.Request) {

	sc, err := r.Cookie(h.server.Config.GetSesssionCookieName())
	if err != nil {
		h.server.responseBadRequest(w, "handleAuthCodeFllow-get-session", err)
		return
	}

	// [x] Check if the provided code value is still active (not expired) in the session store.
	acsm := h.server.Sm.GetAuthCode(sc.Value)
	if acsm == nil {
		h.server.responseBadRequest(w, "handleAuthCodeFllow-get-auth-code", fmt.Errorf("invalid or expired auth code for session %s", sc.Value))
		return
	}

	// [x] If code_verifier has a value - encode it and compare it with code_challenger from the session
	if rb.CodeVerifier != "" {
		if !tools.VerifyCodeChallenge(
			acsm["code_challenger"],
			acsm["code_challenger_method"],
			rb.CodeVerifier) {
			h.server.responseBadRequest(w, "handleAuthCodeFllow-VerifyCodeChallenge", fmt.Errorf("failed to verify the code verifier for session %s", sc.Value))
			return
		}
	}

	// [x] verify the redirect_uri
	if rb.RedirectUri == "" {
		h.server.responseBadRequest(w, "handleAuthCodeFllow-redirect-uri", fmt.Errorf("invalid or missing redirect uri for session %s", sc.Value))
		return
	}

	// rru - registered redirects uris from the client id register.
	rru, err := h.server.Auth.GetClientsRedirectURI(rb.ClientID)
	if err != nil {
		h.server.responseBadRequest(w, "handleAuthCodeFllow-regitred-redirect-uri", fmt.Errorf("unable to acquire register redirect uri for client id %s", rb.ClientID))
		return
	}

	// [x] Verify the uri if registred for the clientID
	var valid_uri bool
	for _, u := range rru {
		if u == rb.RedirectUri {
			valid_uri = true
			break
		}
	}

	if !valid_uri {
		h.server.responseBadRequest(w, "handleAuthCodeFllow-compare-redirect-uri", fmt.Errorf("not registered redirect uri for client id %s", rb.ClientID))
		return
	}

	// [x] 1. Call issue Access Token Method
	cid := core.ClientID(rb.ClientID)
	uid := core.UserID("") // [!]
	c := core.Client{ClientID: core.ClientID(rb.ClientID)}

	oidt := h.server.Auth.IssueIvmIDToken(uid, cid)
	at, err := h.server.Auth.IssueAccessToken(oidt, &c)
	if err != nil {
		h.server.responseUnauth(w, "handleAuthCodeFllow-issue-accessToken", fmt.Errorf("error issue access token %s", err.Error()))
		return
	}

	// [x] 2. Take the value of AT and RT and store them in Session Store using session Manager
	// [x] 3. SM to generate a new sessionID with state "Auth" and set it in the session cookie.
	err = h.server.Sm.SessionAuth(w, r, at.AccessToken, at.RefreshToken)
	if err != nil {
		h.server.responseUnauth(w, "handleAuthCodeFllow-sm-sessionAuth", fmt.Errorf("error issue new authenticated session %s", err.Error()))
		return
	}

	// redirect back to web app page (registered for the client id)
	http.Redirect(w, r, rb.RedirectUri, http.StatusSeeOther)
}

// TODO [dev]:
// handleRefTokenFllow performs the checks and logic for refresh_token grant_type fllow
func (h *oauthHandler) handleRefTokenFllow(
	rb *core.AuthRequestBody,
	w http.ResponseWriter,
	r *http.Request) {

	fmt.Fprintf(w, "post body is %v", rb)
}
