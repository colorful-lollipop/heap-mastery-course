#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_CYAN    "\033[36m"

// Test results
int total_tests = 0;
int passed_tests = 0;

#define TEST_START(name) \
    do { \
        total_tests++; \
        printf("\n" COLOR_BLUE "[Test %d] " COLOR_RESET "%s\n", total_tests, name); \
    } while(0)

#define TEST_PASS() \
    do { \
        passed_tests++; \
        printf("  " COLOR_GREEN "✓ PASS" COLOR_RESET "\n"); \
    } while(0)

#define TEST_FAIL(msg) \
    do { \
        printf("  " COLOR_RED "✗ FAIL" COLOR_RESET ": %s\n", msg); \
    } while(0)

#define TEST_INFO(msg) \
    do { \
        printf("  " COLOR_CYAN "→ " COLOR_RESET "%s\n", msg); \
    } while(0)

// Check GCC version
void check_gcc_version() {
    TEST_START("GCC Version");

    FILE *pipe = popen("gcc --version | head -n1", "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            TEST_INFO(buffer);

            // Check version (need 9.0+ for modern features)
            if (strstr(buffer, "9.") || strstr(buffer, "10.") ||
                strstr(buffer, "11.") || strstr(buffer, "12.")) {
                TEST_PASS();
            } else {
                TEST_FAIL("GCC version should be 9.0 or higher");
            }
        }
        pclose(pipe);
    } else {
        TEST_FAIL("Could not run gcc");
    }
}

// Check glibc version
void check_glibc_version() {
    TEST_START("GLIBC Version");

    FILE *pipe = popen("ldd --version | head -n1", "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            TEST_INFO(buffer);

            // Most heap techniques work with glibc 2.27+
            if (strstr(buffer, "2.27") || strstr(buffer, "2.28") ||
                strstr(buffer, "2.29") || strstr(buffer, "2.30") ||
                strstr(buffer, "2.31") || strstr(buffer, "2.32") ||
                strstr(buffer, "2.33") || strstr(buffer, "2.34") ||
                strstr(buffer, "2.35")) {
                TEST_PASS();
            } else {
                TEST_INFO("Recommended: glibc 2.27-2.35 for best compatibility");
                TEST_PASS();
            }
        }
        pclose(pipe);
    } else {
        TEST_FAIL("Could not check glibc version");
    }
}

// Check GDB
void check_gdb() {
    TEST_START("GDB Debugger");

    FILE *pipe = popen("gdb --version | head -n1", "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            TEST_INFO(buffer);
            TEST_PASS();
        }
        pclose(pipe);
    } else {
        TEST_FAIL("GDB not found. Install with: sudo apt-get install gdb");
    }
}

// Check Pwndbg
void check_pwndbg() {
    TEST_START("Pwndbg (Recommended)");

    FILE *pipe = popen("gdb -q -ex 'pi pwndbg.heap.heap' -ex 'quit' 2>&1 | head -n1", "r");
    if (pipe) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            if (strstr(buffer, "heap") || strstr(buffer, "Chunks")) {
                TEST_INFO("Pwndbg is installed and loaded");
                TEST_PASS();
            } else {
                TEST_INFO("Pwndbg not detected in GDB");
                TEST_INFO("Install from: https://github.com/pwndbg/pwndbg");
                TEST_FAIL("Pwndbg not found");
            }
        }
        pclose(pipe);
    }
}

// Check Python and pwntools
void check_pwntools() {
    TEST_START("Python3 & Pwntools");

    FILE *pipe = popen("python3 -c 'import pwn; print(pwn.__version__)' 2>&1", "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            if (strstr(buffer, "Traceback")) {
                TEST_FAIL("Pwntools not found. Install: pip3 install pwntools");
            } else {
                TEST_INFO(buffer);
                TEST_PASS();
            }
        }
        pclose(pipe);
    }
}

// Check compiler protections
void check_protections() {
    TEST_START("Binary Protections Support");

    // Test if we can compile without stack protector
    system("echo 'int main(){return 0;}' | gcc -fno-stack-protector -x c - -o /tmp/test_protect 2>&1");

    if (access("/tmp/test_protect", F_OK) == 0) {
        TEST_INFO("Can compile without stack protector: ✓");
        unlink("/tmp/test_protect");
    } else {
        TEST_FAIL("Cannot disable stack protector");
    }

    // Test if we can compile without PIE
    system("echo 'int main(){return 0;}' | gcc -no-pie -x c - -o /tmp/test_pie 2>&1");

    if (access("/tmp/test_pie", F_OK) == 0) {
        TEST_INFO("Can compile without PIE: ✓");
        unlink("/tmp/test_pie");
        TEST_PASS();
    } else {
        TEST_FAIL("Cannot disable PIE");
    }
}

// Check heap debugging tools
void check_heap_tools() {
    TEST_START("Heap Debugging Tools");

    // Check checksec
    FILE *pipe = popen("which checksec 2>&1", "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != NULL && !strstr(buffer, "not found")) {
            TEST_INFO("checksec: ✓");
        }
        pclose(pipe);
    }

    // Check if we can inspect /proc/self/maps
    if (access("/proc/self/maps", R_OK) == 0) {
        TEST_INFO("/proc/self/maps: ✓");
        TEST_PASS();
    } else {
        TEST_FAIL("Cannot read /proc/self/maps");
    }
}

// Check project structure
void check_project_structure() {
    TEST_START("Project Structure");

    const char *required_paths[] = {
        "level01_overflow",
        "level02_uaf",
        "level03_fastbin_dup",
        "level04_tcache",
        "level05_heap_spray",
        "level06_feng_shui",
        "level07_advanced",
        "common",
        "docs",
        NULL
    };

    int all_exist = 1;
    for (int i = 0; required_paths[i] != NULL; i++) {
        if (access(required_paths[i], F_OK) == 0) {
            TEST_INFO(required_paths[i]);
        } else {
            TEST_FAIL("Missing: " required_paths[i]);
            all_exist = 0;
        }
    }

    if (all_exist) {
        TEST_PASS();
    }
}

// Test basic heap operations
void test_heap_operations() {
    TEST_START("Basic Heap Operations");

    // Test malloc
    void *ptr1 = malloc(32);
    void *ptr2 = malloc(64);

    if (ptr1 && ptr2) {
        TEST_INFO("malloc: ✓");

        free(ptr1);
        free(ptr2);

        TEST_INFO("free: ✓");
        TEST_PASS();
    } else {
        TEST_FAIL("Basic heap operations failed");
    }
}

int main() {
    printf("\n");
    printf("═════════════════════════════════════════════════════\n");
    printf("   Heap Mastery Course - Environment Check\n");
    printf("═════════════════════════════════════════════════════\n");

    // Run all checks
    check_gcc_version();
    check_glibc_version();
    check_gdb();
    check_pwndbg();
    check_pwntools();
    check_protections();
    check_heap_tools();
    check_project_structure();
    test_heap_operations();

    // Summary
    printf("\n");
    printf("═════════════════════════════════════════════════════\n");
    printf("   Summary: %d/%d tests passed\n", passed_tests, total_tests);

    if (passed_tests == total_tests) {
        printf("   " COLOR_GREEN "✓ All checks passed!" COLOR_RESET "\n");
        printf("   Your environment is ready for heap exploitation!\n");
    } else {
        printf("   " COLOR_YELLOW "⚠ Some checks failed" COLOR_RESET "\n");
        printf("   Please fix the issues above for the best experience\n");
    }
    printf("═════════════════════════════════════════════════════\n");
    printf("\n");

    return (passed_tests == total_tests) ? 0 : 1;
}
