VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)
BIN     := protection
PREFIX  ?= /usr/local

.PHONY: all build install uninstall clean test vet fmt run

all: build

## build: compile a static binary into ./bin
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BIN) ./cmd/protection

## vet: run go vet
vet:
	go vet ./...

## test: run unit tests
test:
	go test ./...

## fmt: gofmt the tree
fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

## run: build and run a one-off scan against the default config
run: build
	./bin/$(BIN) scan

## install: install the binary + systemd unit (requires root)
install: build
	install -Dm0755 bin/$(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	install -Dm0644 packaging/protection.service $(DESTDIR)/etc/systemd/system/protection.service
	@echo "Installed. Next:"
	@echo "  sudo $(PREFIX)/bin/$(BIN) config init"
	@echo "  sudo systemctl daemon-reload && sudo systemctl enable --now protection"

## uninstall: remove installed files
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	rm -f $(DESTDIR)/etc/systemd/system/protection.service

## clean: remove build artifacts
clean:
	rm -rf bin
