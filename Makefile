PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin

BINARY_NAME = b3rsum
SOURCE_FILES = main.go

.PHONY: all build clean install uninstall test fmt vet

all: build

build:
	go build -o $(BINARY_NAME) $(SOURCE_FILES)

clean:
	rm -f $(BINARY_NAME)
	go clean

install: build
	install -v -d "$(DESTDIR)$(BINDIR)/"
	install -m 0755 -v $(BINARY_NAME) "$(DESTDIR)$(BINDIR)/$(BINARY_NAME)"

uninstall:
	rm -vf "$(DESTDIR)$(BINDIR)/$(BINARY_NAME)"

test:
	go test -v ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

deps:
	go mod tidy
	go mod download

release: clean fmt vet
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o $(BINARY_NAME)-linux-amd64 $(SOURCE_FILES)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o $(BINARY_NAME)-darwin-amd64 $(SOURCE_FILES)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o $(BINARY_NAME)-windows-amd64.exe $(SOURCE_FILES)
