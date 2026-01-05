// Level 3: Fastbin Double Free
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
    printf("\n🎉 Flag: %s\n", flag);
}

int main() {
    void *chunks[10];
    int count = 0;
    int choice, idx, size;
    char data[256];

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("═══════════════════════════════════════════════════\n");
    printf("   Level 3: Fastbin Double Free Challenge\n");
    printf("═══════════════════════════════════════════════════\n\n");

    printf("Menu:\n");
    printf("  1. Alloc (size < 128)\n");
    printf("  2. Free\n");
    printf("  3. Edit\n");
    printf("  4. Print\n");
    printf("  5. Check win condition\n");
    printf("  6. Exit\n\n");

    while (1) {
        printf("> ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Size: ");
                scanf("%d", &size);
                if (size > 0 && size < 128) {
                    chunks[count] = malloc(size);
                    printf("Allocated at %p (index %d)\n", chunks[count], count);
                    count++;
                } else {
                    printf("Invalid size\n");
                }
                break;

            case 2:
                printf("Index: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count) {
                    free(chunks[idx]);
                    printf("Freed chunk %d\n", idx);
                    // 漏洞：没有清空指针！可以 double free
                }
                break;

            case 3:
                printf("Index: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count) {
                    printf("Data: ");
                    read(0, chunks[idx], size);
                }
                break;

            case 4:
                printf("Index: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count) {
                    printf("Data: %s\n", (char*)chunks[idx]);
                }
                break;

            case 5:
                // 目标：通过 fastbin dup 控制某个地址
                if (count > 0) {
                    // 显示当前值和目标值
                    unsigned long current_value = 0;
                    if (chunks[0]) {
                        current_value = *(unsigned long*)chunks[0];
                    }
                    printf("Target: 0x4141414141414141\n");
                    printf("Current: 0x%016lx\n", current_value);

                    // 检查是否能控制特定地址
                    if (current_value == 0x4141414141414141) {
                        winner();
                    } else {
                        printf("Hint: Use double free to allocate chunks[0] multiple times!\n");
                    }
                }
                break;

            case 6:
                return 0;

            default:
                printf("Invalid\n");
        }
    }
}
