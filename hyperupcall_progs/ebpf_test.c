#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <fcntl.h>
#include <signal.h>
#include "ebpf_test.skel.h"

static struct ebpf_test_bpf *skel;

static void cleanup(int signum) {
	if (skel) {
		ebpf_test_bpf__detach(skel);
		ebpf_test_bpf__destroy(skel);
	}
	exit(signum);
}

int other_main(int argc, char **argv) {
	int err;

	// Set up signal handler for Ctrl+C
	signal(SIGINT, cleanup);

	// Open BPF application
	skel = ebpf_test_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Load & verify BPF programs
	err = ebpf_test_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		cleanup(1);
	}

	// Attach BPF program
	err = bpf_program__attach_xdp(skel->skeleton->progs[0].prog[0], 2);
	if (err == NULL) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		cleanup(1);
	}
	
	// Find BPF map
	struct bpf_map* map = bpf_object__find_map_by_name(skel->obj, "packets");
	if (!map) {
		fprintf(stderr, "Failed to find map 'packets'\n");
		cleanup(1);
	}

	int map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to open map 'packets'\n");
		cleanup(1);
	}

	unsigned long long *arr = mmap(NULL, 1024 * sizeof(unsigned long long), PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (arr == MAP_FAILED) {
		fprintf(stderr, "Failed to mmap map 'packets'\n");
		cleanup(1);
	}
	
	// Wait for Ctrl+C
	while (1) {
		unsigned int key = 0;
		unsigned long long value = -1;
		if (bpf_map__lookup_elem(map, &key, sizeof(key), &value, sizeof(value), 0) < 0) {
			fprintf(stderr, "Failed to lookup key %u\n", key);
		}
		else {
        	printf("key: %u, value: %llu\n", key, value);
			printf("mmapped value: %llu\n", arr[key]);
		}
        sleep(2);
	}

	return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main() {
	int r;
	const char *file_path = "output/ebpf_test.bpf.o";
	struct bpf_program *prog;
	struct bpf_link *link;
	struct bpf_object *obj;

    int fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open file");
        return 1;
    }

    struct stat fileStat;
    if (fstat(fd, &fileStat) == -1) {
        perror("Failed to get file size");
        close(fd);
        return 1;
    }
    off_t fileSize = fileStat.st_size;

    void* fileData = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE | MAP_POPULATE , fd, 0);
    if (fileData == MAP_FAILED) {
        perror("Failed to mmap file");
        close(fd);
        return 1;
    }
/////////////////////
	obj = bpf_object__open_mem(fileData, fileSize, NULL);


	if (obj == NULL) {
		fprintf(stderr, "Failed to open BPF object file '%s'\n", file_path);
		return 1;
	}

	r = bpf_object__load(obj);
	if (r < 0) {
		fprintf(stderr, "Failed to load BPF object file '%s'\n", file_path);
		return 1;
	}

	prog = bpf_object__next_program(obj, NULL);
	if (prog == NULL) {
		fprintf(stderr, "Failed to find BPF program in file '%s'\n", file_path);
		return 1;
	}

	printf("program name: %s\n", bpf_program__name(prog));

	link = bpf_program__attach_xdp(prog, 2);
	if (link == NULL) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
	}


	// Find BPF map
	struct bpf_map* map = bpf_object__find_map_by_name(obj, "packets");
	if (!map) {
		fprintf(stderr, "Failed to find map 'packets'\n");
		cleanup(1);
	}

	int map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to open map 'packets'\n");
		cleanup(1);
	}

	unsigned long long *arr = mmap(NULL, 1024 * sizeof(unsigned long long), PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (arr == MAP_FAILED) {
		fprintf(stderr, "Failed to mmap map 'packets'\n");
		cleanup(1);
	}
	
	// Wait for Ctrl+C
	// while (1) {
	
	for (int i = 0; i < 3; i++) {
		unsigned int key = 0;
		unsigned long long value = -1;
		if (bpf_map__lookup_elem(map, &key, sizeof(key), &value, sizeof(value), 0) < 0) {
			fprintf(stderr, "Failed to lookup key %u\n", key);
		}
		else {
        	printf("key: %u, value: %llu\n", key, value);
			printf("mmapped value: %llu\n", arr[key]);
		}
        sleep(2);
	}

	bpf_link__destroy(link);
    return 0;
}