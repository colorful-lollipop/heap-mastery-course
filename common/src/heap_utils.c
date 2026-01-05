#include "heap_utils.h"
#include "debug_utils.h"
#include <unistd.h>
#include <string.h>

// Get the size of a chunk from its size field
size_t get_chunk_size(void *chunk) {
    if (chunk == NULL) return 0;

    chunk_info_t *c = (chunk_info_t *)chunk;
    size_t size = c->size & ~0x7;  // Clear the 3 LSB flag bits
    return size;
}

// Print information about a single chunk
void print_chunk_info(void *chunk) {
    if (chunk == NULL) {
        DEBUG_ERROR("NULL chunk pointer");
        return;
    }

    chunk_info_t *c = (chunk_info_t *)chunk;
    size_t size = c->size;
    size_t actual_size = size & ~0x7;
    int prev_inuse = size & 0x1;
    int is_mmapped = size & 0x2;
    int non_main_arena = size & 0x4;

    printf("  Address: %p\n", chunk);
    printf("  Size field: 0x%zx\n", size);
    printf("  Actual size: 0x%zx (%zu bytes)\n", actual_size, actual_size);
    printf("  Flags: %s%s%s\n",
           prev_inuse ? "PREV_INUSE " : "",
           is_mmapped ? "IS_MMAPED " : "",
           non_main_arena ? "NON_MAIN_ARENA" : "");

    // Print fd/bk if free
    if (!prev_inuse || (actual_size >= 0x80)) {
        printf("  fd: %p\n", c->fd);
        printf("  bk: %p\n", c->bk);
    }

    // Print some data
    printf("  Data (first 16 bytes): ");
    unsigned char *data = (unsigned char *)chunk + 0x10;
    for (int i = 0; i < 16 && i < actual_size - 0x10; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// Print heap layout starting from a given address
void print_heap_layout(void *heap_start, size_t num_chunks) {
    printf("\n");
    printf("========================================\n");
    printf("Heap Layout (starting at %p)\n", heap_start);
    printf("========================================\n");

    unsigned char *ptr = (unsigned char *)heap_start;

    for (size_t i = 0; i < num_chunks; i++) {
        printf("\n--- Chunk %zu ---\n", i);
        print_chunk_info(ptr);

        size_t chunk_size = get_chunk_size(ptr);
        if (chunk_size == 0) {
            DEBUG_ERROR("Invalid chunk size, stopping dump");
            break;
        }
        ptr += chunk_size;
    }

    printf("\n========================================\n");
}

// Analyze and print current heap state
void analyze_heap(void) {
    void *heap_start = get_heap_start();
    if (heap_start == NULL) {
        DEBUG_ERROR("Could not determine heap start");
        return;
    }

    size_t heap_size = get_heap_size();
    printf("Heap start: %p\n", heap_start);
    printf("Heap size: 0x%zx bytes\n", heap_size);

    // Print first 10 chunks
    print_heap_layout(heap_start, 10);
}

// Try to get heap start address (brk)
void *get_heap_start(void) {
    void *p = sbrk(0);
    if (p == (void *)-1) {
        return NULL;
    }

    // This is a rough approximation
    // Real implementation would parse /proc/self/maps
    return (void *)((uintptr_t)p - 0x20000);  // Approximate
}

// Get approximate heap size
size_t get_heap_size(void) {
    void *p = sbrk(0);
    if (p == (void *)-1) {
        return 0;
    }
    return 0x21000;  // Approximate for simple programs
}

// Allocate and print chunk info
void *allocate_chunk(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        DEBUG_ERROR("malloc failed");
        return NULL;
    }

    DEBUG_HEAP("Allocated %zu bytes at %p", size, ptr);
    PRINT_CHUNK((void *)((char *)ptr - 0x10));  // Print chunk header

    return ptr;
}

// Free chunk and print info
void free_chunk(void *chunk) {
    if (chunk == NULL) {
        DEBUG_WARNING("Attempting to free NULL pointer");
        return;
    }

    DEBUG_HEAP("Freeing chunk at %p", chunk);
    PRINT_CHUNK((void *)((char *)chunk - 0x10));

    free(chunk);
}

// Fill chunk with a specific value
void fill_chunk(void *chunk, char value, size_t size) {
    if (chunk == NULL) return;
    memset(chunk, value, size);
}

// Print chunk data
void print_chunk_data(void *chunk, size_t size) {
    if (chunk == NULL) return;

    printf("Data at %p (%zu bytes):\n", chunk, size);
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", ((unsigned char *)chunk)[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

// Placeholder functions for fastbins/tcache
void print_fastbins(void) {
    printf("\n========== FASTBINS ==========\n");
    printf("(Use pwndbg or GDB with heap extensions to see actual fastbins)\n");
    printf("Command in GDB: heap\n");
    printf("==============================\n");
}

void print_tcache(void) {
    printf("\n========== TCACHE ==========\n");
    printf("(Use pwndbg or GDB with heap extensions to see actual tcache)\n");
    printf("Command in GDB: heap\n");
    printf("===========================\n");
}
