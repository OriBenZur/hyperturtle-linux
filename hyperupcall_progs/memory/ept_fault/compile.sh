gcc -g -O0 ept_fault.guest.c ../../hyperupcall.c ../../hyperupcall.h -o ept_fault.guest
clang -g -O2 -target bpf -c ept_fault.bpf.c -o ept_fault.bpf.o