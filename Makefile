# octo-mail build helpers.

.PHONY: build test frontend vet fmt

# Compile committed frontend .js from strict TypeScript (committed-JS model:
# .ts is source, .js is committed so it embeds in the binary reproducibly).
frontend:
	cd webui/assets && tsc -p tsconfig.json

build: frontend
	CGO_ENABLED=0 go build ./...

vet:
	go vet ./...

fmt:
	gofmt -w -s ./cmd ./core ./storage ./projection ./protocol ./mailflow ./security ./ops ./webui ./junkfilter

# Tests share one Postgres; run one package at a time.
test:
	go test -p 1 ./...
