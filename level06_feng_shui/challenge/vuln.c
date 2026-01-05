// Level 6: Heap Feng Shui
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
    printf("\n╔════════════════════════════════════════╗\n");
    printf("║     🎯 Heap Feng Shui Master! 🎯        ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  Flag: %s", flag);
    printf("╚════════════════════════════════════════╝\n");
}

int main() {
    void *chunks[50];
    int count = 0;
    int choice, idx, size;
    char data[512];

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("═══════════════════════════════════════════════════\n");
    printf("   Level 6: Heap Feng Shui Challenge\n");
    printf("   (Advanced Heap Layout Manipulation)\n");
    printf("═══════════════════════════════════════════════════\n\n");

    printf("Menu:\n");
    printf("  1. Alloc (size: 16, 32, 64, 128)\n");
    printf("  2. Free\n");
    printf("  3. Edit\n");
    printf("  4. Print heap info\n");
    printf("  5. Win condition\n");
    printf("  6. Exit\n\n");

    while (1) {
        printf("> ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Size (16/32/64/128): ");
                scanf("%d", &size);
                if (size == 16 || size == 32 || size == 64 || size == 128) {
                    chunks[count] = malloc(size);
                    printf("Allocated chunk[%d] size=%d at %p\n",
                           count, size, chunks[count]);
                    count++;
                } else {
                    printf("Invalid size\n");
                }
                break;

            case 2:
                printf("Index to free: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count) {
                    free(chunks[idx]);
                    printf("Freed chunk[%d]\n", idx);
                }
                break;

            case 3:
                printf("Index: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count && chunks[idx]) {
                    printf("Data: ");
                    read(0, chunks[idx], 256);
                }
                break;

            case 4:
                printf("=== Heap Status ===\n");
                for (int i = 0; i < count; i++) {
                    printf("chunk[%d] @ %p: ", i, chunks[i]);
                    if (chunks[i]) {
                        printf("%.16s...\n", (char*)chunks[i]);
                    } else {
                        printf("(freed)\n");
                    }
                }
                break;

            case 5:
                // 复杂的胜利条件：需要精确的堆布局
                {
                    int success = 1;
                    // 检查特定布局
                    if (count < 10) success = 0;

                    // 需要 chunk[0] 和 chunk[9] 特定关系
                    if (success && chunks[0] && chunks[9]) {
                        // 它们的地址应该满足特定关系
                        ptrdiff_t diff = (char*)chunks[9] - (char*)chunks[0];
                        // 期望精确的对齐
                        if (diff != 0x200) success = 0;
                    } else {
                        success = 0;
                    }

                    // chunk[5] 应该包含特定内容
                    if (success && chunks[5]) {
                        if (strcmp((char*)chunks[5], "FENG_SHUI") != 0) {
                            success = 0;
                        }
                    } else {
                        success = 0;
                    }

                    if (success) {
                        winner();
                    } else {
                        printf("\n❌ Not yet! Requirements:\n");
                        printf("   - At least 10 chunks\n");
                        printf("   - chunk[9] - chunk[0] = 0x200\n");
                        printf("   - chunk[5] = 'FENG_SHUI'\n");
                        printf("\nHint: Use precise heap grooming!\n");
                    }
                }
                break;

            case 6:
                printf("Good luck!\n");
                return 0;
        }
    }
}
