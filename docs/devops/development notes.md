# Authentication design (TODO: document the selected design)

The general design includes:
  * Build **Ivmanto OAuth** server 
    - ivmauth Cloud Run service. No-public access thus no CORS requests allowed. All authentication request will go over ivmapi (API Gateway).
  * The principle design pattern:
    ![design pattern](/design/auth_patterns/CSD_fig3.jpg)
  * The OAuth server authenticates Ivmanto's web apps through their back-ends
  * The OAuth server authenticates third-party applications clients through API Gateway.

# Authorization design

# SignIn/SignUp providers [openId]

## Google
[openid-config discovery endpoint](https://accounts.google.com/.well-known/openid-configuration)

## Local godoc on web command:
```bash
 godoc -templates=$GOPATH/src/golang.org/x/tools/godoc/static -http=:6060
```
