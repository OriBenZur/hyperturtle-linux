#!/bin/bash
gcc -g hypercall.c -o hypercall
gcc -g unload_hyperupcall.c -o unload_hyperupcall
gcc -g map_hyperupcall_map.c -o map_hyperupcall_map