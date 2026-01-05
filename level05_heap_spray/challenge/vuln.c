// Level 5: Heap Spraying
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FLAG_FILE "flag.txt"
#define SPRAY_COUNT 100

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
    void *chunks[SPRAY_COUNT];
    int count = 0;
    int choice, idx, num;

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("═══════════════════════════════════════════════════\n");
    printf("   Level 5: Heap Spraying Challenge\n");
    printf("═══════════════════════════════════════════════════\n\n");

    printf("Menu:\n");
    printf("  1. Alloc (size 32)\n");
    printf("  2. Alloc spray (N chunks)\n");
    printf("  3. Free\n");
    printf("  4. Free range\n");
    printf("  5. Edit\n");
    printf("  6. Win\n");
    printf("  7. Exit\n\n");

    while (1) {
        printf("> ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                chunks[count] = malloc(32);
                printf("Allocated chunk[%d] at %p\n", count, chunks[count]);
                count++;
                break;

            case 2:
                printf("How many? ");
                scanf("%d", &num);
                for (int i = 0; i < num && count < SPRAY_COUNT; i++) {
                    chunks[count] = malloc(32);
                    count++;
                }
                printf("Allocated %d chunks (total: %d)\n", num, count);
                break;

            case 3:
                printf("Index: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count) {
                    free(chunks[idx]);
                    printf("Freed chunk[%d]\n", idx);
                }
                break;

            case 4:
                printf("Start index: ");
                scanf("%d", &idx);
                printf("Count: ");
                scanf("%d", &num);
                for (int i = 0; i < num && idx + i < count; i++) {
                    free(chunks[idx + i]);
                }
                printf("Freed %d chunks\n", num);
                break;

            case 5:
                printf("Index: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count) {
                    printf("Data: ");
                    read(0, chunks[idx], 100);
                }
                break;

            case 6:
                // 目标：通过堆喷控制 UAF
                // 需要创建特定布局并利用
                if (count > 10) {
                    // 检查是否有特定模式
                    int found = 0;
                    for (int i = 0; i < count - 10; i++) {
                        if (chunks[i] != NULL &&
                            *(unsigned long*)chunks[i] == 0x53505241592121 &&
                            chunks[i+10] != NULL &&
                            *(unsigned long*)chunks[i+10] == 0x53505241592121) {
                            found = 1;
                            break;
                        }
                    }
                    if (found) winner();
                    else printf("Pattern not found. Heap spray more!\n");
                } else {
                    printf("Need more chunks!\n");
                }
                break;

            case 7:
                return 0;
        }
    }
}
