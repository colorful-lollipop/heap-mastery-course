#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FLAG_FILE "flag.txt"

// 简单的用户结构
typedef struct {
    char username[32];
    char bio[64];
    int isAdmin;
} User;

void winner() {
    char flag[128];
    FILE *f = fopen(FLAG_FILE, "r");
    if (f == NULL) {
        printf("[-] Error: Please create %s\n", FLAG_FILE);
        return;
    }
    fread(flag, 1, sizeof(flag), f);
    fclose(f);

    printf("\n╔════════════════════════════════════════╗\n");
    printf("║     Congratulations! 🎉                ║\n");
    printf("║     UAF Exploit Successful!            ║\n");
    printf("╠════════════════════════════════════════╣\n");
    printf("║  Flag: %s", flag);
    printf("╚════════════════════════════════════════╝\n\n");
}

int main() {
    User *user = NULL;
    User *admin = NULL;
    int choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("═══════════════════════════════════════════════════\n");
    printf("   Level 2: Use-After-Free Challenge\n");
    printf("═══════════════════════════════════════════════════\n\n");

    // 分配 admin 用户（有权限）
    admin = (User *)malloc(sizeof(User));
    strcpy(admin->username, "admin");
    strcpy(admin->bio, "Administrator account");
    admin->isAdmin = 1;

    printf("[+] Created admin user at %p\n", admin);
    printf("    Username: %s\n", admin->username);
    printf("    isAdmin: %d\n\n", admin->isAdmin);

    // 分配普通用户
    user = (User *)malloc(sizeof(User));
    printf("[+] Created user at %p\n\n", user);

    printf("Menu:\n");
    printf("  1. Free admin\n");
    printf("  2. Edit user\n");
    printf("  3. Print admin info\n");
    printf("  4. Exit\n\n");

    while (1) {
        printf("> ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                // 释放 admin
                printf("[*] Freeing admin...\n");
                free(admin);
                printf("[+] Admin freed\n");
                // 注意：admin 指针仍然指向释放的内存！
                break;

            case 2:
                // 编辑用户（可能重用释放的 admin 内存）
                printf("[*] Enter username: ");
                scanf("%31s", user->username);
                printf("[*] Enter bio: ");
                scanf("%63s", user->bio);
                printf("[+] User updated\n");
                break;

            case 3:
                // UAF: 使用已释放的 admin 指针
                printf("[*] Admin info:\n");
                printf("  Username: %s\n", admin->username);
                printf("  Bio: %s\n", admin->bio);
                printf("  isAdmin: %d\n", admin->isAdmin);

                // 检查是否成功利用
                if (admin->isAdmin == 0x1337) {
                    winner();
                }
                break;

            case 4:
                printf("[*] Exiting...\n");
                free(user);
                return 0;

            default:
                printf("Invalid choice\n");
        }
    }

    return 0;
}
