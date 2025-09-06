# Dockerfile
FROM golang:1.25.1-alpine

WORKDIR /app

# Install necessary dependencies
RUN apk add --no-cache git

# Copy project files
COPY . .

# Download Go modules
RUN go mod tidy

# Build the application
RUN go build -o auth-service main.go

# Expose port 8080 for the API
EXPOSE 8080

CMD ["./auth-service"]
