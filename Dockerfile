# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.24 AS builder
ENV CGO_ENABLED=0 GO111MODULE=on

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /src

COPY go.mod go.sum ./
# use build cache for modules
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o /out/anomalo-diag .

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=builder /out/anomalo-diag /app/anomalo-diag
USER nonroot:nonroot
ENTRYPOINT ["/app/anomalo-diag"]
