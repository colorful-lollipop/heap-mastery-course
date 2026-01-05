#include "debug_utils.h"
#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

// Hexdump implementation
void hexdump(void *ptr, size_t size) {
    unsigned char *data = (unsigned char *)ptr;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%08zx: ", i);

        // Print hex values
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }

        printf(" ");

        // Print ASCII
        for (j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }

        printf("\n");
    }
}

// Print stack trace
void print_stack(uintptr_t *base, size_t num_words) {
    printf("Stack at %p:\n", base);
    for (size_t i = 0; i < num_words; i++) {
        printf("  [%2zd] %p: 0x%016zx\n", i, &base[i], base[i]);
    }
}

// Print bytes
void print_bytes(void *ptr, size_t size) {
    unsigned char *data = (unsigned char *)ptr;
    printf("Bytes at %p:\n", ptr);
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (size % 16 != 0) printf("\n");
}

// Print registers (platform-specific)
void print_registers(void) {
#ifdef __x86_64__
    printf("Register dump not available without inline assembly\n");
    printf("Use GDB command: info registers\n");
#else
    printf("print_registers() not implemented for this architecture\n");
#endif
}

// Print backtrace
void print_backtrace(void) {
    void *array[10];
    size_t size;

    size = backtrace(array, 10);
    if (size == 0) {
        printf("No backtrace available\n");
        return;
    }

    printf("Backtrace:\n");
    char **strings = backtrace_symbols(array, size);
    if (strings == NULL) {
        perror("backtrace_symbols");
        return;
    }

    for (size_t i = 0; i < size; i++) {
        printf("  %s\n", strings[i]);
    }

    free(strings);
}

// Wait for debugger to attach
void wait_for_debugger(void) {
    printf("Waiting for debugger to attach...\n");
    printf("PID: %d\n", getpid());
    printf("Attach with: gdb -p %d\n", getpid());
    printf("Once attached, set 'continue_debug = 1' and continue\n");

    volatile int continue_debug = 0;
    while (!continue_debug) {
        sleep(1);
    }

    printf("Debugger attached, continuing...\n");
}

// Log file
static FILE *logfile = NULL;

void log_init(const char *filename) {
    logfile = fopen(filename, "a");
    if (logfile == NULL) {
        perror("fopen");
        return;
    }

    time_t now = time(NULL);
    char *time_str = ctime(&now);
    fprintf(logfile, "\n=== Log started at %s", time_str);
    fflush(logfile);
}

void log_close(void) {
    if (logfile != NULL) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        fprintf(logfile, "\n=== Log ended at %s", time_str);
        fclose(logfile);
        logfile = NULL;
    }
}

void log_message(const char *level, const char *fmt, ...) {
    if (logfile == NULL) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(logfile, "[%s] [%s] ", timestamp, level);

    va_list args;
    va_start(args, fmt);
    vfprintf(logfile, fmt, args);
    va_end(args);

    fprintf(logfile, "\n");
    fflush(logfile);
}
