
#include <stdio.h>
#define HYPERCALL_NUMBER 14

int main() {
    // if (argc < 3) {
    //     printf("Please provide two unsigned integers as arguments.\n");
    //     return 1;
    // }

    // unsigned long in1 = strtoul(argv[1], NULL, 10);
    // unsigned long in2 = strtoul(argv[2], NULL, 10);

    // printf("in1: %lu\n", in1);
    // printf("in2: %lu\n", in2);
    unsigned long hypercallNumber = HYPERCALL_NUMBER;
    unsigned long major_id = 0; // Replace with your hypercall arguments
    unsigned long minor_id = 2; // Replace with your hypercall arguments
    unsigned long hypercallResult;
    asm volatile(
    "movq %1, %%rax;"
    "movq %2, %%rbx;"
    "movq %3, %%rcx;"
    "movq %4, %%rdx;"
    "movq %5, %%rsi;"
    "vmcall;"
    "movq %%rax, %0;"
    : "=r"(hypercallResult)
    : "r"(hypercallNumber), "r" (0UL), "r"(minor_id), "r"(minor_id), "r"(minor_id)
    : "%rax", "%rbx", "%rcx", "%rdi", "%rsi", "%rdx");
}