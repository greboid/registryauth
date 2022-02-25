FROM ghcr.io/greboid/dockerfiles/golang:latest as builder

WORKDIR /app
COPY . /app
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -trimpath -ldflags=-buildid= -o main ./cmd/auth
RUN mkdir /data

FROM ghcr.io/greboid/dockerfiles/base:latest

COPY --from=builder --chown=65532:65532 /data /data

COPY --from=builder /app/main /auth
WORKDIR /
CMD ["/auth"]
