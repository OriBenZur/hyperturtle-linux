#!/usr/bin/python
from bcc import BPF
import ctypes
import pyroute2
import subprocess
from time import sleep
import os
bpf_thing = None
XDP_DEV = "ens3"
# XDP_DEV = "vethff56ed1"
# XDP_DEV = "docker0"

# srcIP 132.68.52.224; dstIP 172.17.0.2; dstMAC 02:42:ac:11:00:02; ifindex 6
CONTAINER_DEV_INDEX = 18
ETH_DEV_INDEX = 2
CONTAINER_MAC = (0x02, 0x42, 0xac, 0x11, 0x00, 0x02)
SERVER_MAC = (0x52, 0x54, 0x00, 0x12, 0x34, 0x56)
CLIENT_MAC = (0xac, 0x1f, 0x6b, 0xa1, 0xb1, 0x82) # eno1
CLIENT_MAC = (0x52, 0x54, 0x00, 0x32, 0x4a, 0xc6) # virbr0
CONTAINER_IP = 0xac110002 # 172.17.0.2
# SERVER_IP = 0x8444348e # 132.68.52.142
# SERVER_IP = 0x0a00020f # 10.0.2.15
SERVER_IP = 0xc0a87a4c # 192.168.122.76
CLIENT_IP = 0x844434e0 # 132.68.52.224
SRC_PORT = 11211
DST_PORT = 7999

class DestInfo(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("saddr", ctypes.c_uint32), ("daddr", ctypes.c_uint32),
                ("bytes", ctypes.c_uint64), ("pkts", ctypes.c_uint64),
                ("dmac", ctypes.c_ubyte * 6), ("ifindex", ctypes.c_uint32)]
    
TwoShorts = ctypes.c_uint16 * 2

def do_packet_counting(flags=0):    
    bpf_thing = BPF("packet_counter.c", debug=4)
    bpf_thing.attach_xdp(dev=XDP_DEV, fn=bpf_thing.load_func("hello_packet",
                BPF.XDP), flags=flags)

    while True:
        sleep(2)
        s = ""
        for k, v in bpf_thing["packets"].items():
            s += "Port {}: counter {},".format(k.value, v.value)
        print(s)



if __name__ == "__main__":
    flags = BPF.XDP_FLAGS_SKB_MODE
    do_packet_counting(flags)
    # do_l3_forwarding(flags)
    
# sudo clang -cc1 -triple x86_64-unknown-linux-gnu -emit-llvm-bc -emit-llvm-uselists -disable-free -clear-ast-before-backend -disable-llvm-verifier -discard-value-names -main-file-name main.c -mrelocation-model pic -pic-level 2 -pic-is-pie -fno-jump-tables -mframe-pointer=none -fmath-errno -ffp-contract=on -fno-rounding-math -mconstructor-aliases -target-cpu x86-64 -tune-cpu generic -mllvm -treat-scalable-fixed-error-as-warning -debug-info-kind=constructor -dwarf-version=4 -debugger-tuning=gdb -fcoverage-compilation-dir=/home/ubuntu/shared_folder/linux-5.16-frhost2 -nostdsysteminc -nobuiltininc -resource-dir lib/clang/14.0.0 -isystem /virtual/lib/clang/include -include /lib/modules/5.16.0+/source/include/linux/kconfig.h -include /virtual/include/bcc/bpf.h -include /virtual/include/bcc/bpf_workaround.h -include /virtual/include/bcc/helpers.h -isystem /virtual/include -I /home/ubuntu/shared_folder/hyperupcall_progs/network/packet_counter -D __BPF_TRACING__ -I arch/x86/include/ -I /lib/modules/5.16.0+/build/arch/x86/include/generated -I include -I /lib/modules/5.16.0+/build/include -I arch/x86/include/uapi -I /lib/modules/5.16.0+/build/arch/x86/include/generated/uapi -I include/uapi -I /lib/modules/5.16.0+/build/include/generated/uapi -D __KERNEL__ -D KBUILD_MODNAME="bcc" -O2 -Wno-deprecated-declarations -Wno-gnu-variable-sized-type-not-at-end -Wno-pragma-once-outside-header -Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-unused-value -Wno-pointer-sign -fdebug-compilation-dir=/home/ubuntu/shared_folder/linux-5.16-frhost2 -ferror-limit 19 -fmessage-length=146 -fgnuc-version=4.2.1 -vectorize-loops -vectorize-slp -faddrsig -D__GCC_HAVE_DWARF2_CFI_ASM=1 -o main.bc -x c ./packet_counter.c