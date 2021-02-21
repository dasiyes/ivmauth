# Use the offical golang image to create a binary.
# This is based on Debian and sets the GOPATH to /go.
# https://hub.docker.com/_/golang
# FROM golang:1.15-buster as builder

# My attempt to get eu.gcr.io image
FROM golang:1.16-buster

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
RUN go build -o cmd/ivmauth/ivmauth -v -mod=readonly cmd/ivmauth/ivmauth.go 

# Use the official Debian slim image for a lean production container.
# https://hub.docker.com/_/debian
# https://docs.docker.com/develop/develop-images/multistage-build/#use-multi-stage-builds
FROM debian:buster-slim
RUN set -x && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary to the production image from the builder stage.
COPY --from=builder /ivmauth/cmd/ivmauth/ivmauth /ivmauth/cmd/ivmauth/ivmauth

# Run the web service on container startup.
CMD ["/ivmauth/cmd/ivmauth/ivmauth"]
