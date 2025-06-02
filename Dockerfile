# Stage 1: Build the Go application
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache for dependencies
COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

# Copy the rest of the application source code
COPY . .

# Build the application
# Statically link the binary to ensure it runs on minimal base images
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o /go-bozocrack cmd/go-bozocrack/main.go

# Stage 2: Create the runtime image
FROM alpine:latest

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the compiled binary from the builder stage
COPY --from=builder /go-bozocrack /usr/local/bin/go-bozocrack

# Set the user for the container
USER appuser

# Set the entrypoint for the container
ENTRYPOINT ["/usr/local/bin/go-bozocrack"]

# Default command (optional, can be overridden at runtime)
# CMD ["--help"]
