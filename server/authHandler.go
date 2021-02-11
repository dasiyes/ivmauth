package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"

	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
)

type authHandler struct {
	s      authenticating.Service
	pks    pksrefreshing.Service
	logger kitlog.Logger
}

func (h *authHandler) router() chi.Router {
	r := chi.NewRouter()

	r.Route("/", func(r chi.Router) {
		r.Post("/", h.authenticateRequest)
	})

	r.Method("GET", "/docs", http.StripPrefix("/auth/v1/docs", http.FileServer(http.Dir("authenticating/docs"))))

	return r
}

func (h *authHandler) authenticateRequest(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Authenticate Client
	err := h.s.AuthenticateClient(r)
	if err != nil {
		h.logger.Log("error", err)
		encodeError(ctx, err, w)
		return
	}

	// TODO: get request body
	reqbody, err := h.s.GetRequestBody(r)
	if err != nil {
		h.logger.Log("error", err)
		encodeError(ctx, err, w)
		return
	}

	// Registering auth request
	h.s.RegisterNewRequest(r.Header, *reqbody)

	// Validate auth request
	at, err := h.s.Validate(r.Header, *reqbody)
	if err != nil {
		encodeError(ctx, err, w)
		return
	}

	// TODO: ========  starting point to move to Validate() func
	var ippks *ivmanto.PublicKeySet
	ippks, err = h.pks.GetPKSCache("google", "https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		encodeError(ctx, err, w)
		return
	}
	lengthJWKS := ippks.LenJWKS()
	fmt.Printf("identity provider pks keys length: %#v\n\n", lengthJWKS)

	// validate idToken ==================
	clm, err := jwt.Parse(reqbody.IDToken, func(token *jwt.Token) (interface{}, error) {

		// check the pks from cache
		if lengthJWKS > 0 {
			fmt.Printf("pks [ippks] in cache: %#v\n\n", ippks)
			fmt.Printf("token.Method: %#v;\n\n token header kid: %#v;\n\n", token.Method.Alg(), token.Header["kid"].(string))
		}

		tKid := token.Header["kid"].(string)
		alg := token.Method.Alg()
		fmt.Printf("algorithm from token Header: %#v\n\n", alg)

		rsaPK, err := h.pks.GetRSAPublicKey("google", tKid)
		if err != nil {
			encodeError(ctx, err, w)
			return nil, nil
		}
		fmt.Printf("rsaPK: %#v\n\n", rsaPK)
		return rsaPK, nil
	})
	// ===================================

	if err != nil {
		fmt.Printf("err JWT validation: %#v\n\n", err.Error())
		encodeError(ctx, err, w)
		return
	}
	fmt.Printf("idToken [validated] claims: %#v\n\n", clm)
	// TODO: ========  endpoint to move to Validate() func

	var response = struct {
		AccessToken ivmanto.AccessToken `json:"access_token"`
	}{
		AccessToken: at,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Log("error", err)
		encodeError(ctx, err, w)
		return
	}
}
