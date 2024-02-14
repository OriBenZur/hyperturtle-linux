#include <stdbool.h>
#include <signal.h>
#include <libgen.h>
#include "../../hyperupcall.h"

long hyperupcall_slot, bypass_alloc_prog_slot, remap_prog_slot, pfn_cache_slot, sp_headers_slot, counter_slot, l1_memslots_base_gfns_slot, l1_memslots_npages_slot, l1_memslots_userspace_addr_slot;
unsigned long long *counter_map = MAP_FAILED;
unsigned long long *data_map = MAP_FAILED;
unsigned long long *l1_memslots_base_gfns = MAP_FAILED;
unsigned long long *l1_memslots_npages = MAP_FAILED;
unsigned long long *l1_memslots_userspace_addr = MAP_FAILED;

void sigint_handler(int sig_num) {
    // hyperupcall_unmap_map(hyperupcall_slot, counter_map_slot, counter_map);
    hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
    hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_base_gfns_slot, l1_memslots_base_gfns);
    hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_npages_slot, l1_memslots_npages);
    hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_userspace_addr_slot, l1_memslots_userspace_addr);
    unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
    unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
    unload_hyperupcall(hyperupcall_slot);
    exit(0);
}

int main() {
    int fd;
    char path[2048];
    char *dir_path;
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path)-1);
    if (len != -1) {
        path[len] = '\0';
        printf("Executable path: %s\n", path);

        // Get the directory path
        dir_path = dirname(path);
        printf("Directory path: %s\n", dir_path);
    } else {
        printf("Failed to get executable path\n");
    }
    strcpy(path, dir_path);
    strcpy(dir_path + strlen(dir_path), "/ept_fault.bpf.o");
    printf("Loading hyperupcall from %s\n", path);
    hyperupcall_slot = load_hyperupcall(path);
    unsigned long value;
    if (hyperupcall_slot < 0) {
        printf("Failed to load hyperupcall\n");
        return -1;
    }
    bypass_alloc_prog_slot = link_hyperupcall(hyperupcall_slot, "bypass_alloc_bpf\0", 1, 0);
    if (bypass_alloc_prog_slot < 0) {
        printf("Failed to link hyperupcall bypass_alloc_prog_slot\n");
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    remap_prog_slot = link_hyperupcall(hyperupcall_slot, "update_mapping\0", 1, 1);
    if (remap_prog_slot < 0) {
        printf("Failed to link hyperupcall\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    pfn_cache_slot = hyperupcall_map_map(hyperupcall_slot, "pfn_cache\0", 8*2*PAGE_SIZE, (void **)&data_map);
    if (pfn_cache_slot < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    // sp_headers = hyperupcall_map_map(hyperupcall_slot, "sp_headers\0", PAGE_SIZE, (void **)&counter_map);
    // if (sp_headers < 0) {
    //     printf("Failed to map map\n");
    //     unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
    //     hyperupcall_unmap_map(hyperupcall_slot, pfn_cache, data_map);
    //     unload_hyperupcall(hyperupcall_slot);
    //     return -1;
    // }

    // counter = hyperupcall_map_map(hyperupcall_slot, "counter\0", PAGE_SIZE, (void **)&data_map);
    // if (counter < 0) {
    //     printf("Failed to map map\n");
    //     unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
    //     hyperupcall_unmap_map(hyperupcall_slot, pfn_cache, data_map);
    //     hyperupcall_unmap_map(hyperupcall_slot, sp_headers, counter_map);
    //     unload_hyperupcall(hyperupcall_slot);
    //     return -1;
    // }

    l1_memslots_base_gfns_slot = hyperupcall_map_map(hyperupcall_slot, "l1_memslots_base_gfns\0", PAGE_SIZE, (void **)&l1_memslots_base_gfns);
    if (l1_memslots_base_gfns < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
    //     hyperupcall_unmap_map(hyperupcall_slot, sp_headers, counter_map);
    //     hyperupcall_unmap_map(hyperupcall_slot, counter, data_map);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }
    
    l1_memslots_npages_slot = hyperupcall_map_map(hyperupcall_slot, "l1_memslots_npages\0", PAGE_SIZE, (void **)&l1_memslots_npages);
    if (l1_memslots_npages < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_base_gfns_slot, data_map);
    //     hyperupcall_unmap_map(hyperupcall_slot, sp_headers, counter_map);
    //     hyperupcall_unmap_map(hyperupcall_slot, counter, data_map);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    l1_memslots_userspace_addr_slot = hyperupcall_map_map(hyperupcall_slot, "l1_memslots_userspace_addr\0", PAGE_SIZE, (void **)&l1_memslots_userspace_addr);
    if (l1_memslots_userspace_addr < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_base_gfns_slot, data_map);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_npages_slot, data_map);
    //     hyperupcall_unmap_map(hyperupcall_slot, sp_headers, counter_map);
    //     hyperupcall_unmap_map(hyperupcall_slot, counter, data_map);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    printf("got ptrs: %p %p\n", data_map, counter_map);
    // data_map[0] = 5678;
    // data_map[1] = 56789;
    signal(SIGINT, sigint_handler);

    int i = 0;
    printf("starting loop\n");
    while(true) {
        for (i = 0; i < 8; i++) printf("data_map[%d] = %llx\n", i, data_map[i]);
        sleep(2);
    }

    return 0;
}
