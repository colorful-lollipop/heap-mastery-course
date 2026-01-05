// Level 4: Tcache Poisoning
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
    void *chunks[20];
    int count = 0;
    int choice, idx;

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("═══════════════════════════════════════════════════\n");
    printf("   Level 4: Tcache Poisoning Challenge\n");
    printf("   (glibc 2.26+)\n");
    printf("═══════════════════════════════════════════════════\n\n");

    printf("Menu:\n");
    printf("  1. Alloc (size 32)\n");
    printf("  2. Free\n");
    printf("  3. Edit\n");
    printf("  4. Win\n");
    printf("  5. Exit\n\n");

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
                printf("Index to free: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count) {
                    free(chunks[idx]);
                    printf("Freed chunk[%d]\n", idx);
                    // Tcache double free: 可以多次 free 同一块
                }
                break;

            case 3:
                printf("Index to edit: ");
                scanf("%d", &idx);
                if (idx >= 0 && idx < count) {
                    printf("Data (max 100): ");
                    read(0, chunks[idx], 100);
                }
                break;

            case 4:
                // 目标：通过 tcache poisoning 实现任意写
                if (*(unsigned long long*)chunks[0] == 0xdeadbeefcafebabeULL) {
                    winner();
                } else {
                    printf("Not yet! Target: 0xdeadbeefcafebabeULL\n");
                }
                break;

            case 5:
                return 0;
        }
    }
}
