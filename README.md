# IVMAUTH
IVMAUTH is Ivmanto's implementation of OAuth2 server with OpenID Connect extension.

The services are structured by "domain driven delivery" idiomatic.

## IVMAUTH features

1. Login user with username and password for their accounts in Ivmanto, using authorization code flow.
 - endpoint [/oauth/login]
1. 

# CICD
## Development

### Any changes to be done in short-live features branch. Main branch is protected. Changes to be merged to main branch via pull request.

### Changes merged to main branch will trigger cloud-build trigger 'build-image-ivmauth' in project 'ivm-b-cicd-i2du' and build the image in container registry in 'eu.gcr.io/ivm-bu1-d-sample-base-7fvc/container/ivmauth'. 

### In order to apply the changes into Cloud-Run service, the terraform code in the repository 'bu1-app1-ivmauth' (project: ivm-bu1-c-infra-pipeline-zt6f) should be applied (step-by-step: plan-dev-np-prod) to update the Cloud-Run service in the respective environment.

# Troubleshooting
## Connect to Cloud-Run service (with no public access) from GCP Cloud Shell:
```bash
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" SERVICE_URL

# for ivmauth:
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" ivmauth-svc-development-jvorfhr3ta-ew.a.run.app/oauth/login
```
