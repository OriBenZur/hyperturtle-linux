// #include "../../vmlinux_guest.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */


SEC("xdp")
int pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

