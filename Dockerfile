# Use the offical golang image to create a binary.
# This is based on Debian and sets the GOPATH to /go.
# https://hub.docker.com/_/golang
# FROM golang:1.15-buster as builder
# ---

# My attempt to get eu.gcr.io image
FROM golang:1.19-buster AS build

ARG GITHUB_TOKEN
ARG GITHUB_USERNAME

# Create and change to the app directory.
WORKDIR /ivmauth

# Retrieve application dependencies.
# This allows the container build to reuse cached dependencies.
# Expecting to copy go.mod and if present go.sum.
COPY go.* ./

# Create a .netrc file to allow git to clone private repos
#RUN echo "machine github.com login " . $GITHUB_USERNAME . " password " . $GITHUB_TOKEN > ~/.netrc
#RUN echo $GITHUB_USERNAME

# source: https://medium.com/swlh/go-modules-with-private-git-repository-3940b6835727
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"

RUN env GIT_TERMINAL_PROMPT=1 go mod download
#RUN go mod download 

# Copy local code to the container image.
COPY . ./

# Build the binary.
RUN go build -o cmd/ivmauth/ivmauth -v -mod=readonly ivmauth.go 

# Use the alpine image for a lean production container.
FROM alpine:3.13 AS base
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary to the production image from the builder stage.
COPY --from=build /ivmauth/cmd/ivmauth/ivmauth .
COPY --from=build /ivmauth/config-staging.yaml .
COPY --from=build /ivmauth/version .
COPY --from=build /ivmauth/ui ./ui
COPY --from=build /ivmauth/favicon.ico .

# Run the web service on container startup.
CMD ["./ivmauth", "--env=staging"]
