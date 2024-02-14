#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>


int main() {
    union bpf_attr map_attr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(int),
        .value_size = sizeof(long),
        .max_entries = 1024,
    };
    int map_fd = bpf(BPF_MAP_CREATE, &map_attr, sizeof(map_attr));
    if (map_fd < 0) {
        perror("Failed to create map");
        return 1;
    }
    printf("Map created with fd %d,n", map_fd);
    
    struct bpf_insn prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    union bpf_attr prog_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .insns = ,
        .insn_cnt,
        .license,
        .log_level,
        .log_size,
        .log_buf,
        .kern_version
    }
    
    return 0;
}