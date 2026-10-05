.PHONY: build test run demo docker

build:
	go build -o siem ./cmd/siem
	go build -o loggen ./cmd/loggen

test:
	go vet ./...
	go test -race ./...

run: build
	./siem

# Start the server and feed it simulated traffic with attacks.
demo: build
	./siem & pid=$$!; sleep 1; ./loggen -rate 5 -attack-every 15s; kill $$pid

docker:
	docker build -t mini-siem .
