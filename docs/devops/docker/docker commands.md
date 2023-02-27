## Build docker image

```bash
docker build -t eu.gcr.io/ivm-bu1-d-sample-base-7fvc/container/ivmauth/ivmauth .

# with env vars
docker build --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} --build-arg GITHUB_USERNAME=${GITHUB_USERNAME} -t eu.gcr.io/ivm-bu1-d-sample-base-7fvc/container/ivmauth/ivmauth .
```

## Push the image

```bash
docker push eu.gcr.io/ivm-bu1-d-sample-base-7fvc/container/ivmauth/ivmauth
```

## Run image locally

```bash
docker run \
  --env-file ./_my_files/env.list \
  -v /Users/tonevSr/tmp/ivmauth:/ivmauth:ro \
  -d -p 8060:8080 eu.gcr.io/ivm-bu1-d-sample-base-7fvc/container/ivmauth
```
