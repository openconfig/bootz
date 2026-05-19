FROM golang:1.26 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bootz-http ./http/main

FROM gcr.io/distroless/static-debian12
WORKDIR /www
COPY --from=builder /bootz-http /bootz-http
# HTTP server might need to run as root to bind to port 80.
# hadolint ignore=DL3002
USER nonroot
ENTRYPOINT ["/bootz-http"]
CMD ["-address", ":8080"]  


