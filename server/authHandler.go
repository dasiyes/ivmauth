package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/dasiyes/ivmsesman"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/rs/xid"

	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
)

type authHandler struct {
	aus    authenticating.Service
	pks    pksrefreshing.Service
	logger kitlog.Logger
	sm     *ivmsesman.Sesman
}

func (h *authHandler) router() chi.Router {
	r := chi.NewRouter()

	r.Route("/", func(r chi.Router) {
		r.Post("/", h.authenticateRequest)
		r.Route("/users", func(r chi.Router) {
			r.Post("/", h.userRegistration)
		})
	})

	r.Method("GET", "/docs", http.StripPrefix("/auth/v1/docs", http.FileServer(http.Dir("authenticating/docs"))))

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
	ns := h.sm.SessionStart(w, r)
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
