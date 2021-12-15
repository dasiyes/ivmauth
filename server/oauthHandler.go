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
	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/justinas/nosurf"
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
		r.Post("/register", h.registerUser)
		r.Get("/token", h.validateToken)
		r.Route("/ui", func(r chi.Router) {
			r.Use(noSurf)
			r.Get("/login", h.userLoginForm)
			r.Get("/register", h.userRegisterForm)
		})
	})

	r.Method("GET", "/docs", http.StripPrefix("/auth/v1/docs", http.FileServer(http.Dir("authenticating/docs"))))

	return r
}

// [!] ACF -> S2
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

	// [!] ACF S3 ->
	// GetAPIGWSvcURL will return the host for the api gateway service
	//
	var api_gw_host = h.server.Config.GetAPIGWSvcURL()

	// While the current session id (sid) is defacto pre-session (session before a user is authenticated) - it can be used as CSRFToken.
	var redirectURL = fmt.Sprintf("https://%s/oauth/ui/login?t=%s", api_gw_host, sid)

	// redirect the user to user's Login form to capture its credentials
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// [!] ACF -> S4
// authLogin - validate user's input credentials
func (h *oauthHandler) authLogin(w http.ResponseWriter, r *http.Request) {

	headerContentTtype := r.Header.Get("Content-Type")
	if headerContentTtype != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		h.server.responseBadRequest(w, "authLogin", fmt.Errorf("unsupported media type %s", headerContentTtype))
		return
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.server.responseBadRequest(w, "authLogin", fmt.Errorf("while parsing the form error: %s", err.Error()))
		return
	}

	var email = r.FormValue("email")
	var password = r.FormValue("password")

	// [ ] Check where this is used???
	var cid = r.FormValue("client_id")
	_ = cid

	// Handle CSRF protection
	var formCSRFToken = r.FormValue("csrf_token")
	stc, err := r.Cookie("csrf_token")
	if err == http.ErrNoCookie {
		// [ ] potential CSRF attack - log the request with all possible details
		w.WriteHeader(http.StatusBadRequest)
		h.server.responseBadRequest(w, "authLogin", fmt.Errorf("missing csrf_token cookie: %#v", err))
		return
	}
	// Verifying the CSRF tokens
	if !nosurf.VerifyToken(formCSRFToken, stc.Value) {
		// [ ] potential CSRF attack - log the request with all possible details
		w.WriteHeader(http.StatusBadRequest)
		h.server.responseBadRequest(w, "authLogin", fmt.Errorf("invalid CSRF tokens. [%s]", stc.Value))
		return
	}

	// Getting state value (defacto pre-session id)
	sc, err := r.Cookie(h.server.Config.GetSesssionCookieName())
	if err == http.ErrNoCookie {
		w.WriteHeader(http.StatusBadRequest)
		h.server.responseBadRequest(w, "authLogin", fmt.Errorf("missing session id cookie: %#v", err))
		return
	}
	var state = sc.Value

	_ = level.Debug(h.logger).Log("cid", cid, "email", email, "password", password)

	if email == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.server.responseBadRequest(w, "authLogin", fmt.Errorf("one or more empty manadatory attribute %s", email))
		return
	}

	valid, err := h.server.Auth.ValidateUsersCredentials(email, password)
	if err != nil || !valid {
		_ = level.Error(h.logger).Log("valid", valid, "error", fmt.Sprintf("%v", err))
		h.server.responseUnauth(w, "authLogin", err)
		return
	}

	if valid {
		// the redirect url should be in the format:
		// https://ivmanto.dev/pg/cb?code=AUTH_CODE_HERE&state=THE_STATE_FROM_THE_FORM

		// GetAPIGWSvcURL will return the host for the api gateway service
		api_gw_host := h.server.Config.GetAPIGWSvcURL()
		api_gw_cbp := h.server.Config.GetAPIGWSvcCBP()

		call_back_url := fmt.Sprintf("https://%s%s", api_gw_host, api_gw_cbp)

		// Get the user sub code to use in token request
		usr, err := h.server.IvmSSO.Users.Find(core.UserID(email))
		if err != nil {
			_ = level.Error(h.logger).Log("findUser-error", fmt.Sprintf("%v", err))
			h.server.responseUnauth(w, "authLogin", err)
			return
		}

		var ac = h.server.Sm.GetAuthCode(state)
		subcodestr := fmt.Sprintf("%v", usr.SubCode)
		var redirectURL = fmt.Sprintf("%s?code=%s&state=%s&sc=%s", call_back_url, ac["auth_code"], state, subcodestr)

		// [!] ACF S7 ->
		// redirect to the web application server endpoint dedicated to call-back from /oauth/login
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	h.server.responseUnauth(w, "authLogin", fmt.Errorf("unauthorized user %s", email))
}

// userLoginForm will handle the UI for users Login Form
func (h *oauthHandler) userLoginForm(w http.ResponseWriter, r *http.Request) {

	var td = ssoapp.TemplateData{
		Form: forms.New(nil),
	}

	h.server.IvmSSO.Render(w, r, "login.page.tmpl", &td)
}

// userRegisterForm will handle the UI for the user's registration form
func (h *oauthHandler) userRegisterForm(w http.ResponseWriter, r *http.Request) {

	var td = ssoapp.TemplateData{
		Form: forms.New(nil),
	}

	h.server.IvmSSO.Render(w, r, "register.page.tmpl", &td)
}

// registerUser will handle the registration of a new user as POST request from the UI form
func (h *oauthHandler) registerUser(w http.ResponseWriter, r *http.Request) {

	headerContentTtype := r.Header.Get("Content-Type")
	if headerContentTtype != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		h.server.responseBadRequest(w, "registerUser", fmt.Errorf("unsupported media type %s", headerContentTtype))
		return
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.server.responseBadRequest(w, "registerUser", fmt.Errorf("while parsing the form error: %v", err))
		return
	}

	var names = r.FormValue("names")
	var email = r.FormValue("email")
	var password = r.FormValue("password")

	// [ ] Check where this is used???
	var cid = r.FormValue("client_id")
	_ = cid

	// Handle CSRF protection
	var formCSRFToken = r.FormValue("csrf_token")
	stc, err := r.Cookie("csrf_token")
	if err == http.ErrNoCookie {
		// [ ] potential CSRF attack - log the request with all possible details
		w.WriteHeader(http.StatusBadRequest)
		h.server.responseBadRequest(w, "registerUser", fmt.Errorf("missing csrf_token cookie: %#v", err))
		return
	}
	// Verifying the CSRF tokens
	if !nosurf.VerifyToken(formCSRFToken, stc.Value) {
		// [ ] potential CSRF attack - log the request with all possible details
		w.WriteHeader(http.StatusBadRequest)
		h.server.responseBadRequest(w, "registerUser", fmt.Errorf("invalid CSRF tokens. [%s]", stc.Value))
		return
	}

	// Getting state value (defacto pre-session id)
	sc, err := r.Cookie(h.server.Config.GetSesssionCookieName())
	if err == http.ErrNoCookie {
		w.WriteHeader(http.StatusBadRequest)
		h.server.responseBadRequest(w, "registerUser", fmt.Errorf("missing session id cookie: %#v", err))
		return
	}
	var state = sc.Value

	_ = level.Debug(h.logger).Log("cid", cid, "email", email, "password", password)

	if email == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.server.responseBadRequest(w, "registerUser", fmt.Errorf("one or more empty manadatory attribute %s", email))
		return
	}

	err = h.server.Rgs.RegisterUser(names, email, password, state)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.server.responseIntServerError(w, "registerUser", fmt.Errorf("one or more empty manadatory attribute %s", email))
		return
	}

	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(fmt.Sprintf("user account %s successfully created", email)))
}

// issueToken will return an access token (Ivmanto's IDToken) to the post request
// [ ] verify this is IDToken from provider Ivmanto that follows the OpenIDConnect standard (https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
func (h *oauthHandler) issueToken(w http.ResponseWriter, r *http.Request) {

	// [x] perform a check for content type header - application/json
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		h.server.responseBadRequest(w, "issueToken-check-content-type",
			fmt.Errorf("unsupported content type [%#v] in the request", ct))
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
		h.server.responseBadRequest(w, "issueToken-read-body", err)
		return
	}

	err = json.Unmarshal(b, &rb)
	if err != nil {
		h.server.responseBadRequest(w, "issueToken-json-body-unmarshal", err)
		return
	}

	_ = level.Debug(h.logger).Log("issueToken-body", fmt.Sprintf("%+v", rb))

	switch rb.GrantType {
	case "authorization_code":
		h.handleAuthCodeFlow(&rb, w, r)
		return
	case "refresh_token":
		h.handleRefTokenFllow(&rb, w, r)
		return
	default:
		h.server.responseBadRequest(w, "issueToken-grant-type", fmt.Errorf("unsupported grant_type flow [%s]", rb.GrantType))
		return
	}
}

// handleAuthCodeFllow performs the checks and logic for Authorization_code grant_type flow
func (h *oauthHandler) handleAuthCodeFlow(
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

	// [x] 1. Call issue Ivmanto IDToken and issue Access Token Methods
	cid := core.ClientID(rb.ClientID)
	c := core.Client{ClientID: core.ClientID(rb.ClientID)}

	oidt := h.server.Auth.IssueIvmIDToken(rb.SubCode, cid)
	at, err := h.server.Auth.IssueAccessToken(oidt, &c)
	if err != nil {
		h.server.responseUnauth(w, "handleAuthCodeFllow-issue-accessToken", fmt.Errorf("error issue access token: %v", err))
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

// TODO [dev]: implement handling of the refresh token for re-issue Access Token!
// handleRefTokenFllow performs the checks and logic for refresh_token grant_type fllow
func (h *oauthHandler) handleRefTokenFllow(
	rb *core.AuthRequestBody,
	w http.ResponseWriter,
	r *http.Request) {

	fmt.Fprintf(w, "post body is %v", rb)
}

func (h *oauthHandler) validateToken(w http.ResponseWriter, r *http.Request) {

	oidpn := r.Header.Get("X-Token-Type")
	if oidpn == "" {
		h.server.responseBadRequest(w, "validateToken", fmt.Errorf("empty openID provider name"))
		return
	}
	auh := strings.Split(r.Header.Get("X-Ivm-AT"), " ")
	if len(auh) != 2 || auh[0] != "Bearer" {
		h.server.responseBadRequest(w, "validateToken", fmt.Errorf("invalid request"))
		return
	}

	if err := h.server.Auth.ValidateAccessToken(auh[1], oidpn); err != nil {
		h.server.responseUnauth(w, "validateToken", fmt.Errorf("failed validation error: %v", err))
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`welcome-realm-ivmanto`))
}
