.PHONY: build test e2e vet

build:
	go build -o gk .

test:
	go test .
	node --test tests/*.test.mjs

# Needs: npm install && npx playwright install chromium
e2e:
	npx playwright test

vet:
	go vet ./...
	node --check web/app.js
	node --check web/crypto.js
