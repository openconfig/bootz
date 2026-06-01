FROM golang:1.26 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bootz-dhcp ./dhcp/main

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /bootz-dhcp /bootz-dhcp
# DHCP needs to run as root to bind to port 67 and use raw sockets.
USER nonroot
HEALTHCHECK --interval=5s --timeout=2s --start-period=3s --retries=3 \
  CMD ["/bootz-dhcp", "--healthcheck"]
ENTRYPOINT ["/bootz-dhcp"]

