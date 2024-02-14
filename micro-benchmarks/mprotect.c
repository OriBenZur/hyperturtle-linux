#include <sys/time.h>
#include <sys/mman.h>
#include <stdio.h>

#define PGSIZE ((long int)4096)
#define N_PAGES ((long int)(1))
#define TOTAL_ARR_SIZE ((long int)(PGSIZE * N_PAGES))
#define N_ITERATIONS (1024*1024)

int main() {
    struct timeval start, end;
    char *addr = mmap(NULL, PGSIZE * N_PAGES, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
    char temp;
    if (addr == NULL)
        return -1;
    addr[0] = -1;

    gettimeofday(&start, NULL);
    for (long int i = 0; i < N_ITERATIONS; i++) {
        mprotect(addr, PGSIZE, PROT_READ);
        mprotect(addr, PGSIZE, PROT_READ | PROT_WRITE);
        addr[0] = i;
    }
    gettimeofday(&end, NULL);

    double elapsed_time = ((end.tv_usec - start.tv_usec) / 1000) + ((end.tv_sec - start.tv_sec) * 1000);
    printf("Using mprotect %d times took: %.4lf milli-seconds\n", N_ITERATIONS, elapsed_time);
    return 0;
}