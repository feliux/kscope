package ebpf

//go:generate bpf2go -target bpfel -cc clang -cflags "$BPF_CFLAGS" kscope kscope.bpf.c -- -I.
