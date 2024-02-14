#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>

int main() {
    int fd = open("/sys/bus/pci/devices/0000:05:00.0/resource2", O_RDWR | O_SYNC);
    if (fd < 0) {
        printf("Failed to open resource2\n");
        return -1;
    }

    unsigned long *map = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        printf("Failed to mmap resource0\n");
        return -1;
    }


    while(true) {
        printf("Packets: %ld\n", map[0]);
        sleep(2);
    }
}