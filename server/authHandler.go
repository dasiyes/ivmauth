package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/dasiyes/ivmsesman"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/segmentio/ksuid"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/svc/authenticating"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
)

type authHandler struct {
	aus    authenticating.Service
	pks    pksrefreshing.Service
	logger kitlog.Logger
	sm     *ivmsesman.Sesman
}

func (h *authHandler) router() chi.Router {

	r := chi.NewRouter()
	r.Method("GET", "/metrics", promhttp.Handler())

	r.Route("/", func(r chi.Router) {
		r.Post("/", h.authenticateRequest)
		r.Get("/", h.initAuthCode)
		r.Get("/version", h.version)
		r.Route("/users", func(r chi.Router) {
			r.Post("/", h.userRegistration)
		})
	})

	r.Method("GET", "/docs", http.StripPrefix("/auth/v1/docs", http.FileServer(http.Dir("authenticating/docs"))))

	return r
}

func (h *authHandler) authenticateRequest(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	var client core.Client
	var ok bool

	if v := ctx.Value(Cid); v != nil {
		client, ok = v.(core.Client)
		if !ok {
			core.EncodeError(context.TODO(), http.StatusForbidden, errors.New("invalid client type"), w)
			return
		}
	}

	reqbody, err := h.aus.GetRequestBody(r)
	if err != nil {
		_ = level.Error(h.logger).Log("error ", err)
		core.EncodeError(context.TODO(), http.StatusBadRequest, err, w)
		return
	}

	// Preliminary download JWKS for idToken validation if the x-token-type is not empty
	var tt = r.Header.Get("x-token-type")
	if tt != "" {
		go h.pks.DownloadPKSinCache(tt)
		// TODO: debug to find why it does not work
		// go h.pks.InitOIDProviders()
	}

	// ? Registering auth request (NOT REQUIRED - moved to middleware requestLogging)
	// _, _ = h.aus.RegisterNewRequest(&r.Header, reqbody, &client)

	// Validate auth request. Authenticated client's scope to consider
	at, err := h.aus.Validate(&r.Header, reqbody, h.pks, &client)
	if err != nil {
		core.EncodeError(context.TODO(), http.StatusForbidden, err, w)
		return
	}

	// Get a new session for the authenticated request
	// TODO: instead of creatimg a new Session, get the cookie "ivmid" from the current request and for this session id change the status of the session in the shared database (Firestore - collection sessions).
	ns, err := h.sm.SessionStart(w, r)
	if err != nil {
		_ = level.Error(h.logger).Log("SessionManagerError", err.Error())
	}
	_ = level.Debug(h.logger).Log("sessionID", ns.SessionID())

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(at); err != nil {
		_ = h.logger.Log("error", err)
		core.EncodeError(context.TODO(), http.StatusInternalServerError, err, w)
		return
	}
}

func (h *authHandler) userRegistration(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	var client core.Client
	var ok bool

	if v := ctx.Value(Cid); v != nil {
		client, ok = v.(core.Client)
		if !ok {
			core.EncodeError(context.TODO(), http.StatusForbidden, errors.New("invalid client type"), w)
			return
		}
	}

	// TODO: implement the []scopes that will be registred of the pair client-user
	client.Scopes = []string{}

	reqbody, err := h.aus.GetRequestBody(r)
	if err != nil {
		_ = level.Error(h.logger).Log("error ", err)
		core.EncodeError(context.TODO(), http.StatusBadRequest, err, w)
		return
	}

	usr, err := h.aus.RegisterUser(reqbody.Name, reqbody.Email, reqbody.Password)
	if err != nil {
		_ = level.Error(h.logger).Log("error ", err)
		core.EncodeError(context.TODO(), http.StatusInternalServerError, err, w)
		return
	}

	usr.Password = []byte{}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(usr); err != nil {
		_ = level.Error(h.logger).Log("error-json-enc", err)
		core.EncodeError(context.TODO(), http.StatusInternalServerError, err, w)
		return
	}
}

func (h *authHandler) initAuthCode(w http.ResponseWriter, r *http.Request) {

	// The query is already unescaped in the middleware authenticatedClient
	q := r.URL.Query()
	_ = level.Debug(h.logger).Log("GET-/auth", r.URL.RawQuery, "state", q.Get("state"))

	// TODO: save the pair auth-code & state in the database
	//h.aus.RegisterNewRequest()

	code := ksuid.New().String()
	rurl := "/auth"

	ru := fmt.Sprintf("%s?code=%s&state=%s", rurl, code, q.Get("state"))

	// connect to sessions db and change the sessionState from 'New' to 'AuthCodeInit'
	// This should be done by the SessionManager with saving in the DB
	r.Header.Set("X-Session-State", "AuthCodeInit")

	ok, err := h.sm.ChangeState(w, r)
	if !ok && err != nil {
		_ = level.Error(h.logger).Log("ErrorChangeSessionState", err.Error())
	}

	w.Header().Set("Location", ru)
	w.WriteHeader(http.StatusSeeOther)
	w.Write(nil)
}

// Response to "GET /" with the current version of the Ivmanto's auth service
func (h *authHandler) version(w http.ResponseWriter, r *http.Request) {
	var ver []byte
	var err error

	ver, err = ioutil.ReadFile("version")
	if err != nil {
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(ver)
}
