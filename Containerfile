# Builds a static binary and runs it on distroless, as an unprivileged user.
# Released images: ghcr.io/pr0ton11/cs-netcup-bouncer (linux/amd64, linux/arm64).
#   podman build -t localhost/cs-netcup-bouncer:dev .
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4-trixie@sha256:430985542100b871e108ccc00e8dcc5eef08ca14ee5825e98ebf563d8ffec4ee AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/crowdsec-netcup-bouncer .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/crowdsec-netcup-bouncer /crowdsec-netcup-bouncer
USER nonroot:nonroot
ENTRYPOINT ["/crowdsec-netcup-bouncer"]
