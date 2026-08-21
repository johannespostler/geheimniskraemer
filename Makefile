.PHONY: build test vet

build:
	go build -o gk .

test:
	go test .
	node --test tests/*.test.mjs

vet:
	go vet ./...
	node --check web/app.js
	node --check web/crypto.js
