package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type oauth2Handler struct {
	server *Server
	logger kitlog.Logger
}

func (h *oauth2Handler) router() chi.Router {

	r := chi.NewRouter()
	r.Method("GET", "/metrics", promhttp.Handler())

	r.Route("/", func(r chi.Router) {
		r.Get("/certs", h.serveJWKS)
	})

	return r
}

// serveJWKS will return the Ivmanto's OAuth2 server JWKS as json
func (h *oauth2Handler) serveJWKS(w http.ResponseWriter, r *http.Request) {

	// Sample:
	//
	/* ```json
	{
		"keys": [
			{
				"kty": "RSA",
				"e": "AQAB",
				"use": "sig",
				"kid": "85828c59284a69b54b27483e487c3bd46cd2a2b3",
				"n": "zMHxWuxztMKXdBhv3rImlUvW_yp6nO03cVXPyA0Vyq0-M7LfOJJIF-OdNoRGdsFPHVKCFoo6qGhR8rBCmMxA4fM-Ubk5qKuUqCN9eP3yZJq8Cw9tUrt_qh7uW-qfMr0upcyeSHhC_zW1lTGs5sowDorKN_jQ1Sfh9hfBxfc8T7dQAAgEqqMcE3u-2J701jyhJz0pvurCfziiB3buY6SGREhBQwNwpnQjt_lE2U4km8FS0woPzt0ccE3zsGL2qM-LWZbOm9aXquSnqNJLt3tGVvShnev-GiJ1XfQ3EWm0f4w0TX9fTOkxstl0vo_vW_FjGQ0D1pXSjqb7n-hAdXwc9w",
				"alg": "RS256"
			},
			{
				"kty": "RSA",
				"alg": "RS256",
				"kid": "27c72619d0935a290c41c3f010167138685f7e53",
				"n": "qYuQSAy_tAOFdyAO9Dlf9Ky3wnjrW-a-Qk95Bb0AG2GrQ1-KVADlRmRIe_36bs7QPmfpQ41dVYPmNSI7dTLty1zMjHbMz89Bb63fYm6BYMQKvUk5Ss868JdXzkgLc0qsLQ5EGljPolJpii9h2YrrWkHa4DX6sGfS_i1_bSTqRlYyFMICido85SKIbvyVaedX2uFc3KlawsORjbUzxRGS1Ob3ag7c6rRZV_xqSKxVtxf6xmLh1I-t5EiDh8xjaE1XRUv37TzUvCvv3PM1phmDqG_J0QJMqE2J6SNPdva2SqZGNA9D-l2iW2SPU7BToVgAFjv9vrAxjeWAvZh48txptw",
				"e": "AQAB",
				"use": "sig"
			}
		]
	}
	```
	*/

	te := strconv.FormatInt(time.Now().Unix()+int64(14400), 10)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-XSS-Protection", "0")
	w.Header().Set("Expires", te)
	w.Header().Set("Cache-Control", "public, max-age=18465, must-revalidate, no-transform")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Vary", "Origin, X-Origin, Referer")

	// [ ] Take the JWKS from the proper firestore DB for the Ivmanto OID provider record
	_, err := w.Write([]byte(
		`{
			"keys": [
				{
					"kty": "RSA",
					"e": "AQAB",
					"use": "sig",
					"kid": "85828c59284a69b54b27483e487c3bd46cd2a2b3",
					"n": "zMHxWuxztMKXdBhv3rImlUvW_yp6nO03cVXPyA0Vyq0-M7LfOJJIF-OdNoRGdsFPHVKCFoo6qGhR8rBCmMxA4fM-Ubk5qKuUqCN9eP3yZJq8Cw9tUrt_qh7uW-qfMr0upcyeSHhC_zW1lTGs5sowDorKN_jQ1Sfh9hfBxfc8T7dQAAgEqqMcE3u-2J701jyhJz0pvurCfziiB3buY6SGREhBQwNwpnQjt_lE2U4km8FS0woPzt0ccE3zsGL2qM-LWZbOm9aXquSnqNJLt3tGVvShnev-GiJ1XfQ3EWm0f4w0TX9fTOkxstl0vo_vW_FjGQ0D1pXSjqb7n-hAdXwc9w",
					"alg": "RS256"
				},
				{
					"kty": "RSA",
					"alg": "RS256",
					"kid": "27c72619d0935a290c41c3f010167138685f7e53",
					"n": "qYuQSAy_tAOFdyAO9Dlf9Ky3wnjrW-a-Qk95Bb0AG2GrQ1-KVADlRmRIe_36bs7QPmfpQ41dVYPmNSI7dTLty1zMjHbMz89Bb63fYm6BYMQKvUk5Ss868JdXzkgLc0qsLQ5EGljPolJpii9h2YrrWkHa4DX6sGfS_i1_bSTqRlYyFMICido85SKIbvyVaedX2uFc3KlawsORjbUzxRGS1Ob3ag7c6rRZV_xqSKxVtxf6xmLh1I-t5EiDh8xjaE1XRUv37TzUvCvv3PM1phmDqG_J0QJMqE2J6SNPdva2SqZGNA9D-l2iW2SPU7BToVgAFjv9vrAxjeWAvZh48txptw",
					"e": "AQAB",
					"use": "sig"
				}
			]
		}`))

	// [ ] Handle the error properlly
	if err != nil {
		w.WriteHeader(500)
	}
}
