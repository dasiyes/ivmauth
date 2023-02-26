# Build and run locally

## Build local executable
```bash
go build -o _my_files/cmd/ivmauth -v -mod=readonly ivmauth.go

# make it executable
chmod +x _my_files/cmd/ivmauth
``` 

## Run local executable
```bash

export FIRESTORE_PROJECT_ID=`<firebase_project_id>`
export PORT=8082
export SMTP_PASSWORD=`<smtp_password>`

# run the executable. The key `--env` is required for the local run
./_my_files/cmd/ivmauth --env=staging
```


## Run local docker image as container

[source](https://cloud.google.com/code/docs/vscode/develop-service)

1. In VS Code:
cmd + Shift + P => Cloud Code: Run on Cloud Run Simulator;
