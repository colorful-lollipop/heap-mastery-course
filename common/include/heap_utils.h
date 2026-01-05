#ifndef HEAP_UTILS_H
#define HEAP_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

// Chunk structure for glibc malloc
// Based on glibc malloc implementation
typedef struct chunk_info {
    size_t prev_size;     // Size of previous chunk (only if previous chunk is free)
    size_t size;          // Current chunk size (including header)
    struct chunk_info *fd; // Forward pointer (only if free)
    struct chunk_info *bk; // Backward pointer (only if free)
} chunk_info_t;

// Heap visualization functions
void print_heap_layout(void *heap_start, size_t num_chunks);
void print_chunk_info(void *chunk);
void analyze_heap(void);
void print_fastbins(void);
void print_tcache(void);

// Helper functions
size_t get_chunk_size(void *chunk);
int is_chunk_free(void *chunk);
void *get_heap_start(void);
size_t get_heap_size(void);

// Chunk manipulation utilities
void *allocate_chunk(size_t size);
void free_chunk(void *chunk);
void fill_chunk(void *chunk, char value, size_t size);
void print_chunk_data(void *chunk, size_t size);

// Debug macros
#define PRINT_CHUNK(ptr) printf("Chunk at %p:\n", ptr); print_chunk_info(ptr)
#define HEAP_BARRIER() printf("========== HEAP STATE ==========\n"); analyze_heap(); printf("===============================\n")

#endif // HEAP_UTILS_H
