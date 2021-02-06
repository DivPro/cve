.PHONY: build
build:
	go build -ldflags="-s -w" -o bin/cve main/cve/main.go

.PHONY: debug
debug:
	go build -gcflags '-N -l' -o bin/cve main/cve/main.go

.PHONY: lint
lint:
	./bin/golangci-lint run ./...

.PHONY: lint-prepare
lint-prepare:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s latest

.PHONY: test
test:
	go test -v -short ./...

.PHONY: migrate-prepare
migrate-prepare:
	go get -u github.com/pressly/goose/cmd/goose
	mkdir "./migrations"

.PHONY: migrate-run
migrate-run:
	#goose --dir="migrations" postgres "postgres://pg-user:pg-pass@127.0.0.1:5432/pg-db?sslmode=disable" down && \
	goose --dir="migrations" postgres "postgres://pg-user:pg-pass@127.0.0.1:5432/pg-db?sslmode=disable" up

.PHONY: run
run:
	docker-compose up -d

.PHONY: stop
stop:
	docker-compose down