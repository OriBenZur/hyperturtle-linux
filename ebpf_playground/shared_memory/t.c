// t.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>

#define SHM_SIZE (1 * 1024 * 1024)

int main(int argc, char **argv) {
    char p[3];
    int fd;
    int i;

    fd = open("/sys/bus/pci/devices/0000:00:07.0/resource2", O_RDWR);
    assert(fd != -1);
    read(fd, p, 3);
    // p = mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    // assert(p != NULL);
    // p[0] = 'b';
    // for (i = 0; i < 3; i++) {
    //     printf("%c", p[i]);
    // }
    printf("%c\n", p[0]);

    munmap(p, SHM_SIZE);
    close(fd);

    return 0;
}