# 前置知识

在开始堆漏洞利用学习之前，你需要掌握一些基础知识。

## C 语言要求

### 指针和内存

```c
// 指针基础
int *ptr;           // 指针声明
ptr = &x;           // 获取地址
*ptr = 10;          // 解引用

// 指针运算
ptr + 1;            // 移动 sizeof(int) 字节
(char*)ptr + 1;     // 移动 1 字节

// 函数指针
void (*func_ptr)(void);
func_ptr = &function;
func_ptr();         // 调用函数
```

### 结构体

```c
typedef struct {
    char name[32];
    int age;
    void (*callback)(void);
} User;

User *u = malloc(sizeof(User));
u->age = 25;
u->callback();
```

### 内存管理

```c
void *ptr = malloc(size);  // 分配
free(ptr);                  // 释放
ptr = NULL;                 // 好习惯：释放后置空

// 常见错误
free(ptr);   // ✅
free(ptr);   // ❌ double free
ptr[100] = 0; // ❌ heap overflow
```

### 缓冲区操作

```c
char buf[64];
strcpy(buf, str);       // 危险：不检查大小
strncpy(buf, str, 63);  // 安全
buf[63] = '\0';         // 确保 null 终止

read(0, buf, 100);      // 危险：可能溢出
```

## 计算机基础

### 内存结构

```
高地址
  +------------------+
  |      Stack       |  ← 函数调用栈
  |        ↓         |
  +------------------+
  |        ↑         |
  |       Heap       |  ← 动态分配
  +------------------+
  |      BSS         |  ← 未初始化数据
  +------------------+
  |      Data        |  ← 初始化数据
  +------------------+
  |      Text        |  ← 代码段
低地址
```

### 虚拟内存

- 每个进程有独立的虚拟地址空间
- 页表将虚拟地址映射到物理地址
- ASLR 随机化地址布局

### 数据表示

```c
// 大小端
int x = 0x12345678;
// 小端 (x86): 78 56 34 12
// 大端: 12 34 56 78

// 对齐
struct {
    char a;    // 1 字节
    // 3 字节 padding
    int b;     // 4 字节 (需要 4 字节对齐)
};  // 总共 8 字节
```

## Linux 基础

### 命令行操作

```bash
# 文件操作
ls, cd, pwd, cat, vim

# 编译
gcc program.c -o program

# 调试
gdb ./program

# 权限
chmod +x script.sh
```

### 进程管理

```bash
# 运行程序
./program

# 查看进程
ps aux | grep program

# 查看内存映射
cat /proc/PID/maps

# 查看库依赖
ldd ./program
```

### 系统调用

```bash
# 系统调用跟踪
strace ./program

# 库调用跟踪
ltrace ./program
```

## 汇编语言基础

### x86-64 寄存器

```
通用寄存器:
  RAX, RBX, RCX, RDX
  RSI, RDI, RBP, RSP
  R8-R15

指针和大小:
  RIP: 指令指针
  RSP: 栈指针
  RBP: 栈基址
```

### 基本指令

```asm
mov rax, rbx      ; 复制
lea rax, [rbx+10] ; 加载有效地址
push rax          ; 压栈
pop rbx           ; 出栈
call func         ; 调用函数
ret               ; 返回
```

### 函数调用约定

```
调用前:
  参数: RDI, RSI, RDX, RCX, R8, R9
  返回地址: 压栈

函数内:
  RBP: 保存的栈基址
  局部变量: RSP 下方

返回:
  结果: RAX
  恢复 RBP, RET
```

## 调试基础

### GDB 基本命令

```
(gdb) break main     ; 设置断点
(gdb) run            ; 运行
(gdb) next           ; 单步（不进入函数）
(gdb) step           ; 单步（进入函数）
(gdb) continue       ; 继续
(gdb) print var      ; 打印变量
(gdb) x/10x $rsp     ; 查看内存
(gdb) info registers ; 查看寄存器
```

### Pwndbg 命令

```
(gdb) heap           ; 堆布局
(gdb) fastbins       ; fastbin 链表
(gdb) tcache         ; tcache 状态
(gdb) bins           ; 所有 bins
(gdb) arenas         ; 分配区信息
```

## 安全概念

### 常见漏洞类型

- **缓冲区溢出**：写入超过分配的内存
- **Use-After-Free**：使用已释放的内存
- **Double Free**：释放同一块内存两次
- **类型混淆**：错误解释数据类型

### 保护机制

| 保护 | 作用 | 绕过难度 |
|------|------|----------|
| NX | 禁止执行栈 | 易 |
| ASLR | 随机化地址 | 中 |
| PIE | 随机化代码 | 中 |
| Stack Canary | 栈保护 | 难 |
| Safe Linking | 堆指针保护 | 难 |

## 自检问题

在开始之前，确保你能回答这些问题：

### C 语言
- [ ] 指针和引用的区别？
- [ ] malloc 和 free 如何使用？
- [ ] 什么是内存泄漏？
- [ ] 结构体如何对齐？

### 计算机基础
- [ ] 栈和堆的区别？
- [ ] 虚拟内存是什么？
- [ ] 什么是大小端？

### Linux
- [ ] 如何编译和调试 C 程序？
- [ ] 如何查看进程的内存映射？

### 汇编
- [ ] x86-64 有哪些寄存器？
- [ ] 函数调用时参数如何传递？

## 推荐学习资源

如果某些领域薄弱，可以学习这些资源：

### C 语言
- [C Programming Language](https://www.amazon.com/C-Programming-Language-Brian-Kernighan/dp/0131103628)
- [Pointers in C](https://www.youtube.com/watch?v=2zZLc2NjI8o)

### 计算机基础
- [CSAPP](https://www.amazon.com/Computer-Systems-Programmers-Perspective-3rd/dp/013409266X)
- [x86-64 Assembly](https://www.felixcloutier.com/x86/)

### 安全入门
- [Pwnable.kr](https://pwnable.kr/)
- [Pwnable.tw](https://pwnable.tw/)

## 下一步

准备好后，进入：
- [环境配置](02_environment_setup.md)
- [调试工具](03_debugging_tools.md)
- [可视化图表](VISUAL_DIAGRAMS.md) - 堆结构和攻击技术图解

---

**记住**：基础越扎实，后面的学习越轻松！ 💪
