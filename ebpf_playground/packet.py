#!/usr/bin/python
from bcc import BPF
import ctypes
import pyroute2
import subprocess
from time import sleep
import os
bpf_thing = None
# XDP_DEV = "ens3"
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

def do_packet_forwarding(dev:str, local_ips, outgoing_redirections, incoming_redirections, ifindexs, flags=0) -> BPF:
    bpf_thing = BPF("./xdp-redirect/ebpf/xdp_redirect_py.c")
    devs = bpf_thing.get_table("devmap")
    bpf_local_ips = bpf_thing.get_table("local_ips")
    bpf_outgoing_redirections = bpf_thing.get_table("outgoing_redirections")
    bpf_incoming_redirections = bpf_thing.get_table("incoming_redirections")
    for k, v in local_ips.items():
        bpf_local_ips[ctypes.c_uint32(k)] = ctypes.c_uint32(v)
    for k, v in outgoing_redirections.items():
        bpf_outgoing_redirections[ctypes.c_uint16(k)] = v
    for k, v in incoming_redirections.items():
        bpf_incoming_redirections[ctypes.c_uint16(k)] = v
    for i in ifindexs:
        devs[ctypes.c_int(i)] = ctypes.c_int(i)
    
    bpf_thing.attach_xdp(dev=dev, fn=bpf_thing.load_func("loadbal",
                BPF.XDP), flags=flags)
    return bpf_thing
    # Check how many packets were forwarded
    try:
        while True:
            sleep(2)
            # os.system("clear")
            s = ""
            for k, v in bpf_thing["servers"].items():
                s += "src-dst {}: bytes: {} packets: {},".format(k, v.bytes, v.pkts)
            print(s)
    except KeyboardInterrupt:
        print("Removing filter from device")
        bpf_thing.remove_xdp(dev=XDP_DEV)

    # Detach the program when done
    BPF.remove_xdp(dev=XDP_DEV)


def do_packet_counting(flags=0):    
    bpf_thing = BPF("packet_counter.c")
    bpf_thing.attach_xdp(dev="eno1", fn=bpf_thing.load_func("hello_packet",
                BPF.XDP), flags=flags)
    bpf_thing.remove_xdp(dev="eno1")
    bpf_thing.cleanup()
    return

    while True:
        sleep(2)
        s = ""
        for k, v in bpf_thing["packets"].items():
            s += "Protocol {}: counter {},".format(k.value, v.value)
        print(s)

def do_l2_forwarding():
    bpf_thing = BPF("xdp_l2fwd.c")
    bpf_thing.attach_xdp(dev=XDP_DEV, fn=bpf_thing.load_func("xdp_l2fwd",BPF.XDP))

    while True:
        sleep(2)
        s = ""
        for k, v in bpf_thing["packets"].items():
            s += "Protocol {}: counter {},".format(k.value, v.value)
        print(s)

def do_l3_forwarding():
    bpf_thing = BPF("xdp_l3fwd.c")
    devs = bpf_thing.get_table("xdp_l3fwd_devs")
    ports = bpf_thing.get_table("xdp_l3fwd_ports")
    ports[ctypes.c_int(80)] = ctypes.c_int(80)
    devs[80] = ctypes.c_int(80)
    # bpf_thing["xdp_l3fwd_ports"][ctypes.c_int(11211)]= ctypes.c_int(8)
    # bpf_thing["xdp_l3fwd_devs"][ctypes.c_int(11211)]= ctypes.c_int(8)
    bpf_thing.attach_xdp(dev=XDP_DEV, fn=bpf_thing.load_func("xdp_l3fwd_prog",BPF.XDP))
    while True:
        sleep(2)
        s = ""
        for k, v in bpf_thing["packets"].items():
            s += "Protocol {}: counter {},".format(k.value, v.value)
        print(s)
   



if __name__ == "__main__":
    flags = BPF.XDP_FLAGS_SKB_MODE
    # ip = pyroute2.IPRoute()
    # CONTAINER_IF_INDEX = -1
    # ifindexs = [link['index'] for link in ip.get_links()]
    # ifindexs = [ifindexs[1], ifindexs[CONTAINER_IF_INDEX]]
    # container_dev = ip.get_links()[CONTAINER_IF_INDEX]['attrs'][0][1]
    # # ifindexs = [4]
    # print(ifindexs)
    # local_ips = {CONTAINER_IP : 1, SERVER_IP : 1}
    # # outgoing_redirections = {SRC_PORT : DestInfo(SERVER_IP, 0, 0, 0, SERVER_MAC, ifindexs[0])}
    # # incoming_redirections = {SRC_PORT : DestInfo(0, CONTAINER_IP, 0, 0, CONTAINER_MAC, ifindexs[-1])}
    # outgoing_redirections = {SRC_PORT : DestInfo(SERVER_IP, 0, 0, 0, CLIENT_MAC, ifindexs[0])}
    # incoming_redirections = {SRC_PORT : DestInfo(0, CONTAINER_IP, 0, 0, CONTAINER_MAC, ifindexs[-1])}
    
    
    # host2cont = do_packet_forwarding(container_dev, local_ips, outgoing_redirections, {}, ifindexs, flags)
    # cont2host = do_packet_forwarding("ens3", local_ips, {}, incoming_redirections, ifindexs, flags)
    # try:
    #     while True:
    #         # os.system("clear")
    #         s = ""
    #         for k, v in host2cont["outgoing_redirections"].items():
    #             s += "host2cont {}: bytes: {} packets: {},".format(k, v.bytes, v.pkts)
    #         print(s)
    #         s = ""
    #         for k, v in cont2host["incoming_redirections"].items():
    #             s += "cont2host {}: bytes: {} packets: {},".format(k, v.bytes, v.pkts)
    #         print(s)
    #         sleep(2)
    # except KeyboardInterrupt:
    #     print("Removing filter from device")
    #     cont2host.remove_xdp(dev="ens3")
    #     host2cont.remove_xdp(dev=container_dev)
    #     subprocess.Popen(f'sudo ip link set dev {container_dev} xdpgeneric off && sudo ip link set dev ens3 xdpgeneric off', shell=True)
    do_packet_counting(flags)
    # do_l3_forwarding(flags)
    