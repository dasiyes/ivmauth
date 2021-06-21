package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"github.com/dasiyes/ivmsesman"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/rs/xid"
	"github.com/segmentio/ksuid"

	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
)

var fscontent *embed.FS

type authHandler struct {
	aus    authenticating.Service
	pks    pksrefreshing.Service
	fsc    *embed.FS
	logger kitlog.Logger
	sm     *ivmsesman.Sesman
}

func (h *authHandler) router() chi.Router {

	r := chi.NewRouter()

	r.Route("/", func(r chi.Router) {
		r.Post("/", h.authenticateRequest)
		r.Get("/", h.initAuthCode)
		r.Get("/login", h.loginPage)
		r.Route("/users", func(r chi.Router) {
			r.Post("/", h.userRegistration)
		})
	})

	fscontent = h.fsc
	r.Method("GET", "/docs", http.StripPrefix("/auth/v1/docs", http.FileServer(http.Dir("authenticating/docs"))))
	r.Method("GET", "/assets/", http.StripPrefix("/auth/v1/assets", http.FileServer(http.FS(fscontent))))

	return r
}

func (h *authHandler) authenticateRequest(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	var client ivmanto.Client
	var ok bool

	if v := ctx.Value(Cid); v != nil {
		client, ok = v.(ivmanto.Client)
		if !ok {
			ivmanto.EncodeError(context.TODO(), http.StatusForbidden, errors.New("invalid client type"), w)
			return
		}
	}

	reqbody, err := h.aus.GetRequestBody(r)
	if err != nil {
		_ = level.Error(h.logger).Log("error ", err)
		ivmanto.EncodeError(context.TODO(), http.StatusBadRequest, err, w)
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
		ivmanto.EncodeError(context.TODO(), http.StatusForbidden, err, w)
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
		ivmanto.EncodeError(context.TODO(), http.StatusInternalServerError, err, w)
		return
	}
}

func (h *authHandler) userRegistration(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	var client ivmanto.Client
	var ok bool

	if v := ctx.Value(Cid); v != nil {
		client, ok = v.(ivmanto.Client)
		if !ok {
			ivmanto.EncodeError(context.TODO(), http.StatusForbidden, errors.New("invalid client type"), w)
			return
		}
	}

	reqbody, err := h.aus.GetRequestBody(r)
	if err != nil {
		_ = level.Error(h.logger).Log("error ", err)
		ivmanto.EncodeError(context.TODO(), http.StatusBadRequest, err, w)
		return
	}

	// TODO: implement the scope of the client

	usr, err := h.aus.RegisterUser(reqbody.Name, reqbody.Email, reqbody.Password)
	if err != nil {
		_ = level.Error(h.logger).Log("error ", err)
		ivmanto.EncodeError(context.TODO(), http.StatusInternalServerError, err, w)
		return
	}

	at, _ := h.aus.IssueAccessToken(&ivmanto.IDToken{
		Sub: string(usr.SubCode),
		Jti: xid.New().String(),
	}, &client)

	usr.UpdateRefreshToken(at.RefreshToken)

	if err = h.aus.UpdateUser(usr); err != nil {
		h.logger.Log("error update user in the db", err.Error())
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(at); err != nil {
		_ = h.logger.Log("error", err)
		ivmanto.EncodeError(context.TODO(), http.StatusInternalServerError, err, w)
		return
	}
}

func (h *authHandler) initAuthCode(w http.ResponseWriter, r *http.Request) {

	// The query is already unescaped in the middleware authenticatedClient
	q := r.URL.Query()
	_ = level.Debug(h.logger).Log("GET-/auth", r.URL.RawQuery, "state", q.Get("state"))

	// TODO: save the pair auth-code & state in the database
	h.aus.RegisterNewRequest()

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
func (h *authHandler) loginPage(w http.ResponseWriter, r *http.Request) {
	var page = Page{Ver: "v1.0.0"}

	if pusher, ok := w.(http.Pusher); ok {
		// Push is supported.
		fmt.Printf("...=== PUSH is Supported ===...\n")
		if err := pusher.Push("/assets/stylesheet/ivmdev.min.css", nil); err != nil {
			fmt.Printf("Failed to push-1: %v\n", err)
		}
		if err := pusher.Push("/assets/stylesheet/navbar-top-fixed.css", nil); err != nil {
			fmt.Printf("Failed to push-2\n: %v", err)
		}
		if err := pusher.Push("/assets/js/bootstrap.bundle.min.js", nil); err != nil {
			fmt.Printf("Failed to push-3\n: %v", err)
		}
		if err := pusher.Push("/assets/images/logo.svg", nil); err != nil {
			fmt.Printf("Failed to push-4\n: %v", err)
		}
		if err := pusher.Push("/assets/stylesheet/ivmdev.css.map", nil); err != nil {
			fmt.Printf("Failed to push-5\n: %v", err)
		}

	} else {
		fmt.Printf("...=== PUSH is NOT Supported ===...\n")
	}

	w.Header().Set("Content-Type", "text/html")
	t, _ := template.ParseFS(fscontent, "assets/html/login.html")
	t.Execute(w, page)
}

// Page - data for the login screen (if any required)
type Page struct {
	Ver  string
	Body string
}
