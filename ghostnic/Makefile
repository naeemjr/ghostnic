# GhostNIC build system
# Compiles eBPF objects with clang (preferred) or a local Zig fallback,
# then builds the Go userspace tooling.

PROJECT := ghostnic
BPF_DIR := bpf
BUILD_DIR := build
PIN_DIR := /sys/fs/bpf/$(PROJECT)

# Architecture for CO-RE target macros
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Prefer system clang; fall back to the local Zig toolchain if present.
CLANG := $(shell which clang 2>/dev/null)
ifeq ($(CLANG),)
  ifneq (,$(wildcard .toolchain/zig/zig))
    CC := ./.toolchain/zig/zig cc -target bpfel-freestanding
  else
    CC := clang
  endif
else
  CC := $(CLANG) -target bpf
endif

# Prefer system bpftool; fall back to local copy.
BPFTOOL := $(shell which bpftool 2>/dev/null)
ifeq ($(BPFTOOL),)
  ifneq (,$(wildcard .toolchain/bpftool))
    BPFTOOL := ./.toolchain/bpftool
  else
    BPFTOOL := bpftool
  endif
endif

# Include paths for libbpf headers and Linux UAPI headers.
# On systems with libbpf-dev installed, the first path can be omitted.
BPF_INCLUDE := -I .toolchain/libbpf_headers -I /usr/include -I /usr/include/x86_64-linux-gnu

CFLAGS := -O2 -g -D__TARGET_ARCH_$(ARCH) -Wall -Wextra $(BPF_INCLUDE)
CFLAGS_RELEASE := -O2 -D__TARGET_ARCH_$(ARCH) -Wall -Wextra $(BPF_INCLUDE)

GO := go
GOFLAGS := -v

.PHONY: all bpf go test docker-test clean vmlinux release release-bpf obfuscate arm64

all: bpf go

bpf: $(BUILD_DIR)/ghost_xdp.o $(BUILD_DIR)/ghost_tc.o $(BUILD_DIR)/ghost_dns_hijack.o

$(BUILD_DIR)/ghost_xdp.o: $(BPF_DIR)/ghost_xdp.c $(BPF_DIR)/vmlinux.h $(BPF_DIR)/common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/ghost_tc.o: $(BPF_DIR)/ghost_tc.c $(BPF_DIR)/vmlinux.h $(BPF_DIR)/common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/ghost_dns_hijack.o: $(BPF_DIR)/ghost_dns_hijack.c $(BPF_DIR)/vmlinux.h $(BPF_DIR)/common.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

obfuscate:
	$(GO) run scripts/genobf.go

go: bpf obfuscate
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/ghost-load ./cmd/ghost-load
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/ghost-ctl ./cmd/ghost-ctl
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/ghost-detect ./cmd/ghost-detect

release-bpf: obfuscate | $(BUILD_DIR)
	$(CC) $(CFLAGS_RELEASE) -c $(BPF_DIR)/ghost_xdp.c -o $(BUILD_DIR)/ghost_xdp.o
	$(CC) $(CFLAGS_RELEASE) -c $(BPF_DIR)/ghost_tc.c -o $(BUILD_DIR)/ghost_tc.o
	$(CC) $(CFLAGS_RELEASE) -c $(BPF_DIR)/ghost_dns_hijack.c -o $(BUILD_DIR)/ghost_dns_hijack.o

release: release-bpf obfuscate
	@if command -v garble >/dev/null 2>&1; then \
		garble build $(GOFLAGS) -o $(BUILD_DIR)/ghost-load ./cmd/ghost-load; \
		garble build $(GOFLAGS) -o $(BUILD_DIR)/ghost-ctl ./cmd/ghost-ctl; \
		garble build $(GOFLAGS) -o $(BUILD_DIR)/ghost-detect ./cmd/ghost-detect; \
	else \
		echo "garble not found; install github.com/burrowers/garble or use 'make go'"; \
		exit 1; \
	fi

arm64:
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/ghost-load-arm64 ./cmd/ghost-load
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/ghost-ctl-arm64 ./cmd/ghost-ctl
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/ghost-detect-arm64 ./cmd/ghost-detect

test: bpf obfuscate
	$(GO) test ./pkg/... ./cmd/... ./tests/...

simulate: bpf obfuscate
	$(GO) test -tags=simulation ./tests/... -v

docker-test: all
	docker compose -f tests/docker-compose.yml up --build -d
	$(GO) test -tags=integration ./tests/... || true
	docker compose -f tests/docker-compose.yml down

clean:
	rm -rf $(BUILD_DIR)
	sudo rm -rf $(PIN_DIR) 2>/dev/null || true

vmlinux:
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_DIR)/vmlinux.h; \
	else \
		echo "Kernel BTF is not exposed at /sys/kernel/btf/vmlinux."; \
		echo "Install a kernel with CONFIG_DEBUG_INFO_BTF or copy a vmlinux image."; \
		exit 1; \
	fi

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
