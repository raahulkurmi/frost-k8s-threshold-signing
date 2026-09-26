# B1 baseline (BENCHMARK ONLY; NOTES N54): single-key ExternalJWTSigner.
# Build context: repository root. The key is mounted at runtime, never copied in.
FROM golang:1.27.1-alpine3.24 AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY benchmark/go.mod benchmark/go.sum benchmark/
RUN cd benchmark && go mod download
COPY internal/ internal/
COPY benchmark/b1signer/ benchmark/b1signer/
RUN cd benchmark && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/b1signer ./b1signer

FROM alpine:3.24
RUN adduser -D -H -u 10001 b1
COPY --from=builder /out/b1signer /usr/local/bin/b1signer
USER 10001
ENTRYPOINT ["/usr/local/bin/b1signer"]
