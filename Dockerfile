# syntax=docker/dockerfile:1

ARG GO_VERSION=1.24.0
ARG ALPINE_VERSION=3.20

FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/auth-service main.go

FROM alpine:${ALPINE_VERSION} AS runtime

RUN apk add --no-cache ca-certificates \
    && adduser -D -g '' appuser

WORKDIR /app
COPY --from=builder /out/auth-service /app/auth-service

EXPOSE 8080

USER appuser
ENTRYPOINT ["/app/auth-service"]
