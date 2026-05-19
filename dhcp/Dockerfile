FROM golang:1.26 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bootz-dhcp ./dhcp/main

FROM gcr.io/distroless/static-debian12:latest
COPY --from=builder /bootz-dhcp /bootz-dhcp
# DHCP needs to run as root to bind to port 67 and use raw sockets.
# hadolint ignore=DL3002
USER root
ENTRYPOINT ["/bootz-dhcp"]

