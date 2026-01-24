# Dockerfile
FROM golang:1.23.2-alpine AS builder

WORKDIR /app

# Install necessary dependencies
RUN apk add --no-cache git

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy project files
COPY . .

# Build the application
RUN CGO_ENABLED=0 go build -o /auth-service main.go

FROM alpine:3.20

RUN apk add --no-cache ca-certificates
RUN adduser -D -g '' appuser

WORKDIR /app
COPY --from=builder /auth-service /app/auth-service

# Expose port 8080 for the API
EXPOSE 8080

USER appuser
ENTRYPOINT ["./auth-service"]
