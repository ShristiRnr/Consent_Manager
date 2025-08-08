# 🔨 Build Stage
FROM golang:1.24 AS builder

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build all binaries
RUN mkdir -p bin && \
  for cmd in server genkey migrate retry setup-tenant consentctl; do \
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/$cmd ./cmd/$cmd; \
  done

# 🏃 Runtime Stage
FROM gcr.io/distroless/base-debian11

WORKDIR /app

COPY --from=builder /app/bin /app/bin
COPY --from=builder /app/config /app/config

# Expose a default binary; override in service definitions
ENTRYPOINT ["/app/bin/consentctl"]
