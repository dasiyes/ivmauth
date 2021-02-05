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

	r.Route("/auth", func(r chi.Router) {
		r.Post("/", h.authenticateRequest)
	})

	r.Method("GET", "/docs", http.StripPrefix("/v1/auth/docs", http.FileServer(http.Dir("authenticating/docs"))))

	return r
}

func (h *authHandler) authenticateRequest(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	fmt.Printf("...")

	var request struct {
		GrantType string `json:"grant_type"`
		IDToken   string
		Email     string
		Password  string
		Scope     string
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.logger.Log("error", err)
		encodeError(ctx, err, w)
		return
	}

	var ippks *ivmanto.PublicKeySet
	ippks, err := h.pks.GetPKSCache("google", "https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		err := h.pks.NewPKS("google", "https://www.googleapis.com/oauth2/v3/certs")
		if err != nil {
			encodeError(ctx, err, w)
			return
		}
	}

	// validate idToken ==================
	clm, err := jwt.Parse(request.IDToken, func(token *jwt.Token) (interface{}, error) {

		// check the pks from cache
		if len(ippks.Jwks.Keys) > 0 {
			fmt.Printf("pks in cache: %v", ippks)
			fmt.Printf("\ntoken.Method: %#v;\n kid: %#v;\n", token.Method.Alg(), token.Header["kid"].(string))
		}

		tKid := token.Header["kid"].(string)
		alg := token.Method.Alg()
		fmt.Printf("pks in cache: %v", alg)

		rsaPK, err := h.pks.GetRSAPublicKey("google", tKid)
		if err != nil {
			encodeError(ctx, err, w)
			return nil, nil
		}
		return rsaPK, nil
	})
	// ===================================

	if err != nil {
		encodeError(ctx, err, w)
		return
	}
	fmt.Printf("idToken [validated] claims: %v", clm)

	rs := ivmanto.AuthRequest{}

	at, err := h.s.Validate(rs.SessionID)
	if err != nil {
		encodeError(ctx, err, w)
		return
	}

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
