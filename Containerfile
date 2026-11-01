# Builds a static binary and runs it on distroless, as an unprivileged user.
# Released images: ghcr.io/pr0ton11/cs-netcup-bouncer (linux/amd64, linux/arm64).
#   podman build -t localhost/cs-netcup-bouncer:dev .
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.2-trixie@sha256:47667934874913a449b96faa7ef4777fa285d9ec29126ee80ed61c45b7cccf0e AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/crowdsec-netcup-bouncer .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/crowdsec-netcup-bouncer /crowdsec-netcup-bouncer
USER nonroot:nonroot
ENTRYPOINT ["/crowdsec-netcup-bouncer"]
