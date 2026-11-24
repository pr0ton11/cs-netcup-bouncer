# Builds a static binary and runs it on distroless, as an unprivileged user.
# Released images: ghcr.io/pr0ton11/cs-netcup-bouncer (linux/amd64, linux/arm64).
#   podman build -t localhost/cs-netcup-bouncer:dev .
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/crowdsec-netcup-bouncer .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
COPY --from=build /out/crowdsec-netcup-bouncer /crowdsec-netcup-bouncer
USER nonroot:nonroot
ENTRYPOINT ["/crowdsec-netcup-bouncer"]
