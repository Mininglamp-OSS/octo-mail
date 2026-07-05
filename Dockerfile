# octo-mail container image.
#
# Offline, self-contained build: dependencies are vendored (vendor/), so the
# builder needs no module proxy and no sibling ../mox checkout. The webmail JS is
# committed (webui/assets/app.js) and go:embed'ed, so no Node/tsc step is needed.
FROM golang:1.25 AS builder
WORKDIR /src
COPY . .
# -mod=vendor + GOFLAGS off-proxy: build strictly from vendored sources.
ENV GOFLAGS=-mod=vendor GOPROXY=off CGO_ENABLED=0
RUN go build -o /out/octo-mail ./cmd/octo-mail

# Minimal runtime. Static CGO_ENABLED=0 binary + CA certs for outbound TLS
# (ACME / STARTTLS to remote MX).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/octo-mail /usr/local/bin/octo-mail
# Runtime data dirs (fs blob fallback, junk filter, acme cache) live under /data.
WORKDIR /data
EXPOSE 25 143 587 8080 8081
ENTRYPOINT ["/usr/local/bin/octo-mail"]
CMD ["serve"]
