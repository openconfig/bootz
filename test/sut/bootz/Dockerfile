# If you try to build this Dockerfile manually, make sure you build from the repo root directory.

#checkov:skip=CKV_DOCKER_2

FROM golang:1.26 AS builder
WORKDIR /app
COPY . .
RUN chmod -R o+r ./test/config/
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o ./out/bootz ./server/emulator

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/out/bootz ./bootz
COPY --from=builder /app/test/config/bootz_config.textproto ./bootz_config.textproto
USER nonroot
EXPOSE 15006/tcp
ENTRYPOINT ["/app/bootz"]
CMD ["--alsologtostderr", "--config_file=/app/bootz_config.textproto"]  
