FROM docker.io/golang:1.17.2@sha256:45d45a39258425b0386643efc863b3b3c1481173d64ec6151b18d48b565df9a0 AS builder

WORKDIR /app
COPY . /app
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -gcflags=./dontoptimizeme=-N -ldflags=-s -o /app/main ./cmd/authedreg && \
    find /app -exec touch --date=@0 {} \;
RUN mkdir /data

FROM gcr.io/distroless/static@sha256:07869abb445859465749913267a8c7b3b02dc4236fbc896e29ae859e4b360851

COPY --from=builder --chown=65532:65532 /data /data

COPY --from=builder /app/main /authedreg
CMD ["/authedreg"]