.PHONY: build test run demo docker sigma

build:
	go build -o siem ./cmd/siem
	go build -o loggen ./cmd/loggen

test:
	go vet ./...
	SIGMA_DIR=$(if $(wildcard sigma/rules),$(CURDIR)/sigma,) go test -race ./...

# Download (or update) the SigmaHQ community rules into ./sigma.
sigma:
	@if [ -d sigma/.git ]; then git -C sigma pull --ff-only --depth 1; \
	else git clone --depth 1 https://github.com/SigmaHQ/sigma.git sigma; fi

run: build
	./siem

# Start the server with Sigma rules and the demo blocklist, then feed it
# simulated traffic with attacks.
demo: build sigma
	./siem -config config.demo.yaml & pid=$$!; sleep 2; ./loggen -rate 5 -attack-every 15s; kill $$pid

docker:
	docker build -t mini-siem .
