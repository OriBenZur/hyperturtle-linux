gcc -g -O0 packet_counter.guest.c ../../hyperupcall.c ../../hyperupcall.h -o packet_counter.guest
clang -g -O2 -target bpf -c packet_counter.bpf.c -o packet_counter.bpf.o