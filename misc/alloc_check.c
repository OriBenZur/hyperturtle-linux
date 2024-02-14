#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define PAGE_SIZE 4096


unsigned long long getPhysicalAddress(void* addr) {
    static int pm_fd = 0;
    off_t offset = (off_t)((unsigned long long)addr / PAGE_SIZE) * sizeof(uint64_t);
    uint64_t pfn;

    if (pm_fd == 0) {
        pm_fd = open("/proc/self/pagemap", O_RDONLY);
        if (pm_fd < 0) {
            perror("Failed to open pagemap");
            return 0;
        }
        printf("Opened pagemap %d\n", pm_fd);
    }

    if (pread(pm_fd, &pfn, sizeof(uint64_t), offset) != sizeof(uint64_t)) {
        perror("Failed to read pagemap");
        return 0;
    }
    printf("pfn: %p\n", (void *)pfn);

    if ((pfn & (1ULL << 63)) == 0) {
        printf("Page not present\n");
        return 0;
    }

    // Extract the page frame number from the pagemap entry
    pfn = pfn & 0x7FFFFFFFFFFFFF;
    return (pfn << 12) + ((unsigned long long)addr & 0xFFF);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <number_of_pages>\n", argv[0]);
        return 1;
    }

    int numPages = atoi(argv[1]);
    volatile int *pages[4096];
    unsigned long long hypercallResult, hypercallArg0, hypercallNumber = 20;
    for (int i = 0; i < numPages; i++) {
        pages[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pages[i] == NULL) {
            printf("Memory allocation failed\n");
            return 1;
        }
        pages[i][0] = 0xdead;
        hypercallArg0 = getPhysicalAddress(pages[i]);

        printf("calling hypercall with args: %llx, %llx\n", hypercallNumber, hypercallArg0);
        asm volatile(
            "movq %1, %%rax;"
            "movq %2, %%rbx;"
            "vmcall;"
            "movq %%rax, %0;"
            : "=r"(hypercallResult)
            : "r"(hypercallNumber), "r" (hypercallArg0)
            : "%rax", "%rbx");
        printf("Result: %llx\n", hypercallResult);

        *pages[i] = i; // Write one byte to the page
        if (*pages[i] != i)
            printf("Wrote: %d instead of %d\n", *pages[i], i);
        printf("pages[i][0]: %d\n", pages[i][0]);
    }
    return 0;
}
