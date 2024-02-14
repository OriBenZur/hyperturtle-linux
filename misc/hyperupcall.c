#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#define LOAD_HYPERUPCALL 13
#define UNLOAD_HYPERUPCALL 14
#define LINK_HYPERUPCALL 15
#define UNLINK_HYPERUPCALL 16
#define PAGE_SIZE 4096

uintptr_t getPhysicalAddress(void* addr, int pm_fd) {
    static int pm_fd = 0;
    off_t offset = (off_t)((uintptr_t)addr / PAGE_SIZE) * sizeof(uint64_t);
    uint64_t pfn;

    if (pm_fd == 0) {
        pm_fd = open("/proc/self/pagemap", O_RDONLY);
        if (pm_fd < 0) {
            perror("Failed to open pagemap");
            return 0;
        }
    }

    if (pread(pm_fd, &pfn, sizeof(uint64_t), offset) != sizeof(uint64_t)) {
        perror("Failed to read pagemap");
        return 0;
    }

    if (!(pfn & (1ULL << 63))) {
        printf("Page not present\n");
        return 0;
    }

    // Extract the page frame number from the pagemap entry
    pfn = pfn & 0x7FFFFFFFFFFFFF;

    return pfn + (addr & 0xFFF);
}

/**
 * Gets the physical address of the array of physical addresses to the eBPF programs in the file at file_path.
 * All physical addresses are page-aligned.
 * 
 * @file_path: The path to the file containing the eBPF programs.
 * @pptr_array: Place to store the pointer to the array of physical addresses to the eBPF programs. MUST BE ALLOCATED BY USER
 * @pptr_array_size: Place to store the size of the array of physical addresses to the eBPF programs.
 * 
 * @return: -1 on failure, virtual address of mmaped file on success. This needs to be munmaped by the user.
*/
char *get_bpf_prog_ptr_array(const char *file_path, uintptr_t *pptr_array, size_t *pptr_array_size) {
    struct stat fileStat;
    char* fileData;
    int fd;
    
    fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open file");
        return -1;
    }

    if (fstat(fd, &fileStat) == -1) {
        perror("Failed to get file size");
        close(fd);
        return -1;
    }
    *pptr_array_size = fileStat.st_size;

    fileData = mmap(NULL, *pptr_array_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE, fd, 0);
    if (fileData == MAP_FAILED) {
        perror("Failed to mmap file");
        close(fd);
        return -1;
    }


    uintptr_t fileDataEnd = (uintptr_t)fileData + *pptr_array_size;
    for (uintptr_t addr = (uintptr_t)fileData; addr < fileDataEnd; addr += 4096) {
        int pptr_idx = (addr - (uintptr_t)fileData) / 4096;
        pptr_array[pptr_idx] = getPhysicalAddress((void*)addr);
        if (pptr_array[pptr_idx] == 0) {
            printf("Failed to get page frame number for address %p\n", (void*)addr);
            return -1;
        }
        printf("idx: %d, va: %p pa: %p\n", pptr_idx,  (void*)addr, (void*)(pptr_array[pptr_idx]));
    }

    return fileData;
}

int load_hyperupcall(const char* filepath) {
    off_t fileSize;
    uintptr_t *pptr_array;
    char *fileData;
    uintptr_t pptr_array_phys;

    pptr_array = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    pptr_array_phys = getPhysicalAddress(pptr_array);

    fileData = get_bpf_prog_ptr_array(filepath, pptr_array, &fileSize);
    if (fileData == 0) {
        printf("Failed to get bpf prog ptr array\n");
        return -1;
    }
    
    unsigned long hypercallNumber = LOAD_HYPERUPCALL;
    unsigned long hypercallArg0 = pptr_array_phys;
    unsigned long hypercallArg1 = fileSize; // Replace with your hypercall arguments
    unsigned long hypercallResult;
    printf("Calling hypercall %d with args %ld %ld %ld %ld\n", LOAD_HYPERUPCALL, hypercallArg0, hypercallArg1);
    fflush(stdout);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(hypercallResult)
        : "r"(hypercallNumber), "r" (hypercallArg0), "r"(hypercallArg1)
        : "%rax", "%rbx", "%rcx", "%rdi", "%rsi", "%rdx");

    printf("Hypercall %d returned %ld\n", LOAD_HYPERUPCALL, hypercallResult);
    munmap(pptr_array, 4096);
    munmap(fileData, fileSize);
    return hypercallResult;
}

int link_hyperupcall(uintptr_t prog_name_phys, unsigned long major_id, unsigned long minor_id) {
    unsigned long hypercallNumber = LINK_HYPERUPCALL;
    unsigned long hypercallArg0 = prog_name_phys;
    unsigned long hypercallArg1 = major_id;
    unsigned long hypercallArg2 = minor_id;
    unsigned long hypercallResult;
    printf("Calling hypercall %d with args %ld %ld %ld %ld\n", LINK_HYPERUPCALL, hypercallArg0, hypercallArg1, hypercallArg2);
    fflush(stdout);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "movq %4, %%rdx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(hypercallResult)
        : "r"(hypercallNumber), "r" (hypercallArg0), "r"(hypercallArg1), "r"(hypercallArg2)
        : "%rax", "%rbx", "%rcx", "%rdi", "%rsi", "%rdx");

    printf("Hypercall %d returned %ld\n", LINK_HYPERUPCALL, hypercallResult);
    return hypercallResult;
}

int unlink_hyperupcall(unsigned long hyperupcall_slot, unsigned long program_slot) {
    unsigned long hypercallNumber = UNLINK_HYPERUPCALL;
    unsigned long hypercallArg0 = hyperupcall_slot;
    unsigned long hypercallArg1 = program_slot;
    unsigned long hypercallResult;
    printf("Calling hypercall %d with args %ld %ld %ld %ld\n", UNLINK_HYPERUPCALL, hypercallArg0, hypercallArg1);
    fflush(stdout);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "movq %4, %%rdx;"
        "vmcall;"
        "movq %%rax, %0;"
        : "=r"(hypercallResult)
        : "r"(hypercallNumber), "r" (hypercallArg0), "r"(hypercallArg1)
        : "%rax", "%rbx", "%rcx", "%rdi", "%rsi", "%rdx");

    printf("Hypercall %d returned %ld\n", UNLINK_HYPERUPCALL, hypercallResult);
    return hypercallResult;
}

/**        
* int main(int argc, char** argv) {
*     off_t fileSize;
*     uintptr_t *pptr_array;
*     uintptr_t pptr_array_phys, prog_name_phys;
*     const char* filepath = "/home/ubuntu/shared_folder/hyperupcall_progs/output/ebpf_test.bpf.o";
*     int r, hyperupcall_slot, program_slot;
*
*     char *prog_name = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
*     memcpy(prog_name, "xdp_prog_simple\0", sizeof("xdp_prog_simple\0"));
*     prog_name_phys = getPhysicalAddress(prog_name);
*
*
*     hyperupcall_slot = load_hyperupcall(filepath);
*     if (hyperupcall_slot < 0) {
*         printf("Failed to load hyperupcall\n");
*         return -1;
*     }
*
*     program_slot = link_hyperupcall(prog_name_phys, 0, 2);
*     if (program_slot < 0) {
*         printf("Failed to link hyperupcall\n");
*         return -1;
*     }
*     return 0;
* }
*/
