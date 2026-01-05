#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Flag 文件
#define FLAG_FILE "flag.txt"

// 胜利函数 - 读取 flag
void winner() {
    char flag[128];
    FILE *f = fopen(FLAG_FILE, "r");
    if (f == NULL) {
        printf("[-] Error: Please create %s first!\n", FLAG_FILE);
        printf("[-] Run: echo 'flag{heap_overflow_master}' > %s\n", FLAG_FILE);
        return;
    }

    fread(flag, 1, sizeof(flag), f);
    fclose(f);

    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║     Congratulations! 🎉                ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  You have successfully exploited the   ║\n");
    printf("║  heap overflow vulnerability!          ║\n");
    printf("║                                        ║\n");
    printf("║  Flag: %s", flag);
    printf("║                                        ║\n");
    printf("║  You're on your way to becoming a      ║\n");
    printf("║  heap exploitation master!             ║\n");
    printf("╚════════════════════════════════════════╝\n\n");
}

// 简单的堆溢出漏洞
int main() {
    char *chunk1, *chunk2;
    char input[256];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("═══════════════════════════════════════════════════\n");
    printf("   Level 1: Heap Overflow Challenge\n");
    printf("═══════════════════════════════════════════════════\n\n");

    // 分配第一个 chunk
    chunk1 = (char *)malloc(32);
    printf("[+] Allocated chunk1 at: %p (size: 32)\n", chunk1);

    // 分配第二个 chunk
    chunk2 = (char *)malloc(32);
    printf("[+] Allocated chunk2 at: %p (size: 32)\n\n", chunk2);

    printf("Objective: Overflow chunk1 to control chunk2's content!\n");
    printf("Target: Make chunk2 contain the string 'pwned!'\n\n");

    // VULNERABILITY: read() 允许读取超过 chunk1 的大小
    // 我们可以读取 100 字节到 32 字节的缓冲区中
    printf("Enter data for chunk1 (max 100 bytes): ");

    // 漏洞：读取 100 字节到 32 字节的缓冲区
    // 这会造成堆溢出，覆盖 chunk2 的内容
    read(0, chunk1, 100);

    printf("\n[+] You entered: %s\n", chunk1);
    printf("[+] chunk2 content: %s\n", chunk2);
    printf("[+] chunk2 length: %zu\n", strlen(chunk2));

    // 检查是否成功利用
    if (strcmp(chunk2, "pwned!") == 0) {
        winner();
    } else {
        printf("\n[-] Failed! chunk2 does not contain 'pwned!'\n");
        printf("[-] Try again! Hint: Overflow chunk1 to write into chunk2\n");
    }

    // 清理
    free(chunk1);
    free(chunk2);

    return 0;
}
