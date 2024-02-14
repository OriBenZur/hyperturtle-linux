#include <stdbool.h>
#include <signal.h>
#include <linux/bpf.h>
#include "../../hyperupcall.h"

long hyperupcall_slot, program_slot;

void sigint_handler(int sig_num) {
    unlink_hyperupcall(hyperupcall_slot, program_slot);
    unload_hyperupcall(hyperupcall_slot);
    exit(0);
}

typedef struct rule_t {
    __u32 port;
    __u32 action;
} rule;

int main() {
    hyperupcall_slot = load_hyperupcall("./packet_filter.bpf.o");
    rule pass = {.port = 11211, .action = XDP_PASS}, drop = {.port = 0, .action = XDP_DROP};
    if (hyperupcall_slot < 0) {
        printf("Failed to load hyperupcall\n");
        return -1;
    }

    hyperupcall_map_elem_get_set(hyperupcall_slot, "rules\0", sizeof("rules\0"), 0, &pass, sizeof(pass), true);
    hyperupcall_map_elem_get_set(hyperupcall_slot, "rules\0", sizeof("rules\0"), 1, &drop, sizeof(drop), true);

    hyperupcall_map_elem_get_get(hyperupcall_slot, "rules\0", sizeof("rules\0"), 0, &pass, sizeof(pass));
    printf("port: %d, action: %d\n", pass.port, pass.action);
    hyperupcall_map_elem_get_get(hyperupcall_slot, "rules\0", sizeof("rules\0"), 1, &drop, sizeof(drop));
    printf("port: %d, action: %d\n", drop.port, drop.action);
    
    program_slot = link_hyperupcall(hyperupcall_slot, "packet_filter\0", 0, 5);
    if (program_slot < 0) {
        printf("Failed to link hyperupcall\n");
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    signal(SIGINT, sigint_handler);

    while(true) {
        sleep(2);
        // hyperupcall_map_elem_get_set(hyperupcall_slot, "packets\0", sizeof("packets\0"), 0, &value, sizeof(value), false);
        // printf("packets: %ld\n", value);
    }

    return 0;
}