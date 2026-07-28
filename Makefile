PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin

BINARY_NAME = b3rsum
SOURCE_FILES = main.go

.PHONY: all build clean install uninstall test fmt vet

all: build

build:
	go build -o b3rsum main.go

# Build for Debian 9 compatibility (static binary)
build-debian9:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o b3rsum-debian9 main.go

# Build static binary for maximum compatibility
build-static:
	CGO_ENABLED=0 go build -ldflags="-w -s" -o b3rsum-static main.go

clean:
	rm -f $(BINARY_NAME) b3rsum b3rsum-debian9 b3rsum-static
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
	@echo "No external dependencies required - using b3sum command"
	@which b3sum > /dev/null || (echo "Error: b3sum command not found. Please install BLAKE3 tools." && exit 1)

release: clean fmt vet
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o $(BINARY_NAME)-linux-amd64 $(SOURCE_FILES)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o $(BINARY_NAME)-darwin-amd64 $(SOURCE_FILES)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o $(BINARY_NAME)-windows-amd64.exe $(SOURCE_FILES)
