// Level 7: Advanced Techniques & Mitigation Bypass
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FLAG_FILE "flag.txt"

void winner() {
    char flag[128];
    FILE *f = fopen(FLAG_FILE, "r");
    if (!f) {
        printf("Create %s first!\n", FLAG_FILE);
        return;
    }
    fread(flag, 1, sizeof(flag), f);
    fclose(f);
    printf("\n╔════════════════════════════════════════════════╗\n");
    printf("║     🏆 Ultimate Heap Master! 🏆                 ║\n");
    printf("╠════════════════════════════════════════════════╣\n");
    printf("║  Flag: %s", flag);
    printf("║                                               ║\n");
    printf("║  You have mastered advanced heap              ║\n");
    printf("║  exploitation techniques!                      ║\n");
    printf("╚════════════════════════════════════════════════╝\n");
}

// 目标结构（需要劫持）
typedef struct {
    void (*func_ptr)(void);
    char data[32];
} Target;

Target *target = NULL;

int main() {
    void *chunks[30];
    int count = 0;
    int choice, idx, size;
    char data[512];

    setvbuf(stdout, NULL, _IONBF, 0);

    // 初始化目标
    target = (Target *)malloc(sizeof(Target));
    target->func_ptr = NULL;
    strcpy(target->data, "Secure data");

    printf("═══════════════════════════════════════════════════\n");
    printf("   Level 7: Advanced Heap Exploitation\n");
    printf("   (Safe Linking Bypass, House of Einherjar)\n");
    printf("═══════════════════════════════════════════════════\n\n");

    printf("Target @ %p\n", target);
    printf("  func_ptr: %p\n", target->func_ptr);
    printf("  data: %s\n\n", target->data);

    printf("Menu:\n");
    printf("  1. Alloc\n");
    printf("  2. Free\n");
    printf("  3. Edit\n");
    printf("  4. Print\n");
    printf("  5. Call target function\n");
    printf("  6. Exit\n\n");

    while (1) {
        printf("> ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Size: ");
                scanf("%d", &size);
                if (size > 0 && size < 512) {
                    chunks[count] = malloc(size);
                    printf("Allocated chunk[%d] @ %p\n", count, chunks[count]);
                    count++;
                }
                break;

            case 2:
                printf("Index: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count) {
                    free(chunks[idx]);
                    printf("Freed chunk[%d]\n", idx);
                    // Safe linking 应该保护 fd
                }
                break;

            case 3:
                printf("Index: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count && chunks[idx]) {
                    printf("Data: ");
                    read(0, chunks[idx], size);
                }
                break;

            case 4:
                printf("Index: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count) {
                    printf("chunk[%d] @ %p: ", idx, chunks[idx]);
                    if (chunks[idx]) {
                        printf("%.32s\n", (char*)chunks[idx]);
                    } else {
                        printf("(freed)\n");
                    }
                }
                break;

            case 5:
                printf("Calling target function...\n");
                if (target->func_ptr != NULL) {
                    target->func_ptr();
                } else {
                    printf("func_ptr is NULL\n");
                    printf("Try to hijack it! Target: %p\n", &target->func_ptr);
                }
                break;

            case 6:
                printf("Exiting...\n");
                return 0;

            default:
                printf("Invalid\n");
        }
    }
}
