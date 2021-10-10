FROM reg.g5d.dev/golang@sha256:65e504b0cb4e5df85e2301f47cd3f231768d7b0d5aba59b1201e9c50fdf5e0ac as builder

WORKDIR /app
COPY . /app
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -gcflags=./dontoptimizeme=-N -ldflags=-s -o /app/main ./cmd/auth && \
    find /app -exec touch --date=@0 {} \;
RUN mkdir /data

FROM scratch

COPY --from=builder --chown=appuser /data /data

COPY --from=builder /app/main /auth
USER appuser:appuser
CMD ["/auth"]