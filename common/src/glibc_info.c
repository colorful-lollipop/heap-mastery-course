/*
 * glibc_info.c - Print glibc version and features
 *
 * Use this tool to check which heap exploitation techniques
 * are available on your system.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <gnu/libc-version.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_CYAN    "\033[36m"

void print_feature(const char* name, int enabled) {
    if (enabled) {
        printf("  " COLOR_GREEN "✓" COLOR_RESET " %s: " COLOR_GREEN "Enabled" COLOR_RESET "\n", name);
    } else {
        printf("  " COLOR_RED "✗" COLOR_RESET " %s: " COLOR_RED "Disabled" COLOR_RESET "\n", name);
    }
}

int main() {
    printf("\n");
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║     GLIBC Version & Heap Features Detector         ║\n");
    printf("╚════════════════════════════════════════════════════╝\n\n");

    // Print glibc version
    const char *version = gnu_get_libc_version();
    const char *release = gnu_get_libc_release();

    printf(COLOR_CYAN "GLIBC Version:" COLOR_RESET "\n");
    printf("  Version: %s\n", version);
    printf("  Release: %s\n\n", release);

    // Parse major/minor version
    int major = 0, minor = 0;
    sscanf(version, "%d.%d", &major, &minor);

    // Print heap features based on version
    printf(COLOR_CYAN "Heap Features:" COLOR_RESET "\n");

    // Tcache (glibc 2.26+)
    if (major > 2 || (major == 2 && minor >= 26)) {
        print_feature("Tcache (per-thread cache)", 1);
        printf("    " COLOR_YELLOW "→" COLOR_RESET " Level 4: Tcache Poisoning available\n");
    } else {
        print_feature("Tcache (per-thread cache)", 0);
    }

    // Safe Linking (glibc 2.32+)
    if (major > 2 || (major == 2 && minor >= 32)) {
        print_feature("Safe Linking (fastbin/tcache protection)", 1);
        printf("    " COLOR_YELLOW "→" COLOR_RESET " Level 7: Advanced techniques require bypass\n");
    } else {
        print_feature("Safe Linking (fastbin/tcache protection)", 0);
        printf("    " COLOR_YELLOW "→" COLOR_RESET " Level 3: Fastbin dup easier without Safe Linking\n");
    }

    // Thread cache (general)
    print_feature("Fastbins", 1);
    printf("    " COLOR_YELLOW "→" COLOR_RESET " Level 3: Fastbin Double Free available\n");

    print_feature("Small/Large Bins", 1);
    printf("    " COLOR_YELLOW "→" COLOR_RESET " Advanced: House of Einherjar available\n");

    printf("\n");

    // Exploitability Matrix
    printf(COLOR_CYAN "Exploit Compatibility Matrix:" COLOR_RESET "\n");
    printf("┌─────────────────────┬────────┬────────┐\n");
    printf("│ Technique           │ Available │ Level  │\n");
    printf("├─────────────────────┼────────┼────────┤\n");

    // Basic overflow
    printf("│ Heap Overflow       │   " COLOR_GREEN "✓" COLOR_RESET "    │   1    │\n");

    // UAF
    printf("│ Use-After-Free      │   " COLOR_GREEN "✓" COLOR_RESET "    │   2    │\n");

    // Fastbin dup (harder with Safe Linking)
    if (major < 2 || (major == 2 && minor < 32)) {
        printf("│ Fastbin Double Free  │   " COLOR_GREEN "✓" COLOR_RESET "    │   3    │\n");
    } else {
        printf("│ Fastbin Double Free  │   " COLOR_YELLOW "~" COLOR_RESET "    │   3*   │\n");
    }

    // Tcache
    if (major > 2 || (major == 2 && minor >= 26)) {
        printf("│ Tcache Poisoning     │   " COLOR_GREEN "✓" COLOR_RESET "    │   4    │\n");
    } else {
        printf("│ Tcache Poisoning     │   " COLOR_RED "✗" COLOR_RESET "    │  N/A   │\n");
    }

    // Heap Spraying
    printf("│ Heap Spraying        │   " COLOR_GREEN "✓" COLOR_RESET "    │   5    │\n");

    // Heap Feng Shui
    printf("│ Heap Feng Shui       │   " COLOR_GREEN "✓" COLOR_RESET "    │   6    │\n");

    // Advanced
    if (major > 2 || (major == 2 && minor >= 32)) {
        printf("│ Safe Linking Bypass  │   " COLOR_GREEN "✓" COLOR_RESET "    │   7    │\n");
    } else {
        printf("│ Safe Linking Bypass  │   " COLOR_YELLOW "~" COLOR_RESET "    │   7*   │\n");
    }

    printf("└─────────────────────┴────────┴────────┘\n");
    printf("\n");
    printf("Legend: " COLOR_GREEN "✓" COLOR_RESET " = Fully available, "
           COLOR_YELLOW "~" COLOR_RESET " = Modified/Simplified, "
           COLOR_RED "✗" COLOR_RESET " = Not available\n");
    printf("* = Level may be simplified for this glibc version\n");

    printf("\n");
    return 0;
}
