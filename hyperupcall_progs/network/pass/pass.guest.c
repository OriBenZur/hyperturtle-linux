#include <stdbool.h>
#include <signal.h>
#include "../../hyperupcall.h"

long hyperupcall_slot, program_slot;

void sigint_handler(int sig_num) {
    unlink_hyperupcall(hyperupcall_slot, program_slot);
    unload_hyperupcall(hyperupcall_slot);
    exit(0);
}

int main() {
    hyperupcall_slot = load_hyperupcall("pass.bpf.o");
    long value;
    if (hyperupcall_slot < 0) {
        printf("Failed to load hyperupcall\n");
        return -1;
    }
    program_slot = link_hyperupcall(hyperupcall_slot, "pass\0", 0, 5);
    if (program_slot < 0) {
        printf("Failed to link hyperupcall\n");
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    signal(SIGINT, sigint_handler);

    while(true) {
        sleep(2);
    }

    return 0;
}