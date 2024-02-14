#include <sys/time.h>
#include <sys/mman.h>
#include <stdio.h>

#define PGSIZE ((long int)4096)
#define N_PAGES ((long int)(1000*1000*5))
#define TOTAL_ARR_SIZE ((long int)(PGSIZE * N_PAGES))

int main() {
    struct timeval start, end;
    char *addr = mmap(NULL, PGSIZE * N_PAGES, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (addr == NULL)
        return -1;
    gettimeofday(&start, NULL);
    for (long int i = 0; i < TOTAL_ARR_SIZE; i+= PGSIZE)
        addr[i] = 1;
    gettimeofday(&end, NULL);
    double elapsed_time = ((end.tv_usec - start.tv_usec) / 1000) + ((end.tv_sec - start.tv_sec) * 1000);
    printf("Demanding %ld pages took: %.4lf milli-seconds\n",N_PAGES, elapsed_time);
    return 0;
}