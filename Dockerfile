# syntax=docker/dockerfile:1
# One image, seven processes and the migrate subcommand:
#   docker run <image> api | rid-ingest | dp-poller | manned-ingest |
#                      detect | tsdb-writer | picture-ws | migrate [--help]
# CGO_ENABLED=0, distroless static, non-root (plan §10).

FROM golang:1.27-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
# Spec 06 T11: the test harness is never linked into a binary.
RUN if go list -deps ./cmd/... | grep -q 'github.com/rootxkit/uspace-authority/internal/ltest'; then \
      echo "a binary links internal/ltest" >&2; exit 1; fi
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    ld="-s -w -X github.com/rootxkit/uspace-authority/internal/proc.Version=${VERSION}"; \
    mkdir -p /out/libexec /out/var/evidence /out/var/archive; \
    for p in api rid-ingest dp-poller manned-ingest detect tsdb-writer picture-ws; do \
      go build -ldflags "$ld" -o /out/libexec/$p ./cmd/$p; \
    done; \
    go build -ldflags "$ld -X main.libexecDir=/usr/libexec/uspace-authority" -o /out/uspace-authority ./cmd/uspace-authority

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/libexec/ /usr/libexec/uspace-authority/
COPY --from=build /out/uspace-authority /uspace-authority
# The mount points of deploy/compose.yaml's evidence and archive volumes,
# owned by the non-root user, so a new named volume starts writable
# (Docker copies the directory's ownership into an empty volume).
COPY --from=build --chown=nonroot:nonroot /out/var/ /var/lib/uspace-authority/
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/uspace-authority"]
