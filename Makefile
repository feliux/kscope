
VMLINUX ?= internal/ebpf/vmlinux.h
BIN_DIR ?= bin
BIN ?= $(BIN_DIR)/kscope

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	BPF_TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
	BPF_TARGET_ARCH := arm64
else ifeq ($(ARCH),arm64)
	BPF_TARGET_ARCH := arm64
else
	BPF_TARGET_ARCH := x86
endif

BPF_CFLAGS := -O2 -g -Wall -Werror -D__TARGET_ARCH_$(BPF_TARGET_ARCH)

.PHONY: all tools btf generate build run test clean

all: build

tools:
	go install github.com/cilium/ebpf/cmd/bpf2go@latest

btf: $(VMLINUX)

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

generate: $(VMLINUX)
	BPF_CFLAGS="$(BPF_CFLAGS)" BPF_TARGET_ARCH="$(BPF_TARGET_ARCH)" go generate ./internal/ebpf

build: generate
	mkdir -p $(BIN_DIR)
	go build -o $(BIN) ./cmd/kscope

run: build
	sudo $(BIN)

test:
	go test ./...

clean:
	rm -f $(BIN)
	rm -f internal/ebpf/*_bpfel.o internal/ebpf/*_bpfeb.o
	rm -f internal/ebpf/*_bpfel.go internal/ebpf/*_bpfeb.go
