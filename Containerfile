# Builds a static binary and runs it on distroless, as an unprivileged user.
# Released images: ghcr.io/pr0ton11/cs-netcup-bouncer (linux/amd64, linux/arm64).
#   podman build -t localhost/cs-netcup-bouncer:dev .
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.3-trixie@sha256:c65ecfe613b539ac74c62a4c3b2c27e8f8a6076384c8f27e8a3c0f3be17cc385 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/crowdsec-netcup-bouncer .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/crowdsec-netcup-bouncer /crowdsec-netcup-bouncer
USER nonroot:nonroot
ENTRYPOINT ["/crowdsec-netcup-bouncer"]
