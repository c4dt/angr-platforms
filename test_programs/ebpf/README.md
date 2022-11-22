Binary programs for eBPF compiled on Ubuntu

Compiling C programs to eBPF bytecode:

```
clang -target bpf prog.c -o prog.o
```

To see bytecode:

```
llvm-objdump -d prog.o
```
