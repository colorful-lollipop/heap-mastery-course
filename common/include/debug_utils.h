#ifndef DEBUG_UTILS_H
#define DEBUG_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Color codes for terminal output
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"

// Debug print macros
#define DEBUG_INFO(fmt, ...) \
    printf(COLOR_BLUE "[INFO] " COLOR_RESET fmt "\n", ##__VA_ARGS__)

#define DEBUG_SUCCESS(fmt, ...) \
    printf(COLOR_GREEN "[SUCCESS] " COLOR_RESET fmt "\n", ##__VA_ARGS__)

#define DEBUG_WARNING(fmt, ...) \
    printf(COLOR_YELLOW "[WARNING] " COLOR_RESET fmt "\n", ##__VA_ARGS__)

#define DEBUG_ERROR(fmt, ...) \
    printf(COLOR_RED "[ERROR] " COLOR_RESET fmt "\n", ##__VA_ARGS__)

#define DEBUG_HEAP(fmt, ...) \
    printf(COLOR_MAGENTA "[HEAP] " COLOR_RESET fmt "\n", ##__VA_ARGS__)

// Memory dump functions
void hexdump(void *ptr, size_t size);
void print_stack(uintptr_t *base, size_t num_words);
void print_bytes(void *ptr, size_t size);

// GDB-like helpers
void print_registers(void);
void print_backtrace(void);
void wait_for_debugger(void);

// Logging functions
void log_init(const char *logfile);
void log_close(void);
void log_message(const char *level, const char *fmt, ...);

// Conditional compilation
#ifdef DEBUG_MODE
    #define DBG_PRINT(fmt, ...) DEBUG_INFO(fmt, ##__VA_ARGS__)
#else
    #define DBG_PRINT(fmt, ...) do {} while(0)
#endif

#endif // DEBUG_UTILS_H
