# frost-k8s: threshold RSA ExternalJWTSigner
export GOTOOLCHAIN := go1.27.1

.PHONY: all build vet test test-unit test-malicious check-images e2e e2e-keep e2e-down legacy

all: build vet test

build:
	go build ./...

vet:
	go vet ./...
	go vet -tags testmalicious ./...

## Unit + integration (T1–T12) + T5 with the test-only malicious signer build tag.
test: test-unit test-malicious

test-unit:
	go test -count=1 -timeout 30m ./...

test-malicious:
	go test -count=1 -timeout 30m -tags testmalicious -run 'TestMaliciousSignerExcluded' -v ./test/

## T13: no secret material in any image layer (needs docker).
check-images:
	scripts/check-images.sh

## Kubernetes e2e (E1–E8). Linux host with Docker Engine only.
e2e:
	test/e2e/run.sh

e2e-keep:
	test/e2e/run.sh --keep

e2e-down:
	-kind delete cluster --name tk8s
	-FROST_UID=$$(id -u) docker compose -p tk8s -f deploy/docker-compose.yml down -v --remove-orphans

## The abandoned FROST prototype still compiles behind its tag.
legacy:
	cd legacy/frost && go build -tags legacy ./...
