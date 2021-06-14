# Use the offical golang image to create a binary.
# This is based on Debian and sets the GOPATH to /go.
# https://hub.docker.com/_/golang
# FROM golang:1.15-buster as builder

# My attempt to get eu.gcr.io image
FROM golang:1.16-buster AS build

# Create and change to the app directory.
WORKDIR /ivmauth

# Retrieve application dependencies.
# This allows the container build to reuse cached dependencies.
# Expecting to copy go.mod and if present go.sum.
COPY go.* ./
RUN go mod download

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
COPY --from=build /ivmauth/ivmauth .
COPY --from=build /ivmauth/config-staging.yaml .
COPY --from=build /ivmauth/version .

# Run the web service on container startup.
CMD ["./ivmauth", "--env=staging"]
