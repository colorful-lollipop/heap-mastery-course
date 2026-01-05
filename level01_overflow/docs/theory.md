# Level 1: 堆溢出理论详解

## 目录
1. [堆的基本概念](#堆的基本概念)
2. [GLIBC Malloc 简介](#glibc-malloc-简介)
3. [Chunk 结构详解](#chunk-结构详解)
4. [堆分配过程](#堆分配过程)
5. [堆溢出原理](#堆溢出原理)
6. [内存布局分析](#内存布局分析)

---

## 堆的基本概念

### 什么是堆？

堆（Heap）是进程地址空间中用于动态内存分配的区域。与栈（Stack）不同：

| 特性 | 栈 | 堆 |
|------|---------------------|---------------------|
| 分配方式 | 自动（编译器） | 手动（malloc/free） |
| 分配方向 | 高地址 → 低地址 | 低地址 → 高地址 |
| 大小限制 | 通常 1-8MB | 仅受虚拟内存限制 |
| 速度 | 快（移动指针） | 较慢（查找空闲块） |
| 生命周期 | 函数作用域 | 程序员控制 |

### 堆在进程地址空间中的位置

```
+------------------+ 0xFFFFFFFFFFFFFFFF
|   Kernel Space   |
+------------------+
|      Stack       |  ← 栈向下增长
|        ↓         |
+------------------+
|        ↑         |
|      Heap        |  ← 堆向上增长
|       ⋮          |
+------------------+
|      BSS         |
+------------------+
|      Data        |
+------------------+
|      Text        |  ← 代码段
+------------------+ 0x0000000000000000
```

### 系统调用

堆操作主要使用以下系统调用：

1. **brk()** - 设置程序断点（堆的结束位置）
2. **mmap()** - 映射匿名内存（大块分配）
3. **munmap()** - 取消映射

```c
void *brk(void *addr);           // 设置堆顶
void *sbrk(intptr_t increment);  // 相对移动堆顶
```

---

## GLIBC Malloc 简介

### ptmalloc2

Linux 使用 **ptmalloc2** 作为默认的内存分配器，它是 glibc 的一部分。

### 核心概念

1. **Arena（分配区）**: 管理堆的独立区域
   - Main arena: 主分配区
   - Thread arenas: 线程私有分配区

2. **Chunk（块）**: 堆的基本单位
   - Allocated chunk: 已分配的块
   - Free chunk: 空闲块

3. **Bins（箱）**: 管理空闲块的容器
   - Fast bins: 小块快速回收
   - Tcache: 每线程缓存（glibc 2.26+）
   - Small bins: 中等大小
   - Large bins: 大块
   - Unsorted bin: 中转站

---

## Chunk 结构详解

### 完整 Chunk 结构

```c
struct malloc_chunk {
    size_t prev_size;    // 前一个块的大小（如果前一块空闲）
    size_t size;         // 当前块的大小 + 标志位

    struct malloc_chunk *fd;  // Forward pointer（仅空闲时）
    struct malloc_chunk *bk;  // Backward pointer（仅空闲时）

    // 只有在使用时才有用户数据
    // 空闲时可能还有 fd_nextsize, bk_nextsize
};
```

### 内存布局

```
已分配的 Chunk:
+------------------+ chunk 指针
| prev_size (8B)   |  <- 任意值（前块占用时）
+------------------+
| size (8B)        |  <- 实际大小 | PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA
+------------------+
|                  |
|  User Data       |  <- malloc() 返回的地址
|  ...             |
+------------------+

空闲的 Chunk:
+------------------+
| prev_size (8B)   |  <- 前一个块的大小
+------------------+
| size (8B)        |  <- 实际大小 | 0 (PREV_INUSE=0, 表示前块空闲)
+------------------+
| fd (8B)          |  <- Forward 指针（指向 bin 中的下一个块）
+------------------+
| bk (8B)          |  <- Backward 指针（指向 bin 中的前一个块）
+------------------+
|                  |
|  Unused Space    |  <- 未使用的空间（可被分配）
|  ...             |
+------------------+
```

### Size 字段详解

size 字段的最低 3 位用作标志位：

```
+--------+--------+--------+--------------------------+
|  位2   |  位1   |  位0   |         位[63:3]         |
+--------+--------+--------+--------------------------+
| NON_   | IS_    | PREV_  |      实际大小（8字节对齐）|
| MAIN_  | MMAPED | INUSE  |                          |
| ARENA  |        |        |                          |
+--------+--------+--------+--------------------------+
```

**标志位**：
- **PREV_INUSE (0x1)**: 前一个块是否在使用
- **IS_MMAPPED (0x2)**: 是否通过 mmap 分配
- **NON_MAIN_ARENA (0x4)**: 是否属于非主分配区

**实际大小计算**：
```c
size_t actual_size = chunk->size & ~0x7;  // 清除低 3 位
```

### 为什么 8 字节对齐？

1. 性能：对齐的内存访问更快
2. 方便：利用最低 3 位存储标志位
3. 要求：x86-64 上指针是 8 字节

---

## 堆分配过程

### malloc() 的流程

```
malloc(size)
    |
    ├─ size ≤ 0? → 返回 NULL
    |
    ├─ size 调整（对齐，加上头部大小）
    |
    ├─ 检查 tcache（glibc 2.26+）
    |   └─ 有合适的块 → 返回
    |
    ├─ 检查 fast bins
    |   └─ 有合适的块 → 返回
    |
    ├─ 检查 small bins
    |   └─ 有合适的块 → 返回
    |
    ├─ 检查 large bins
    |   └─ 有合适的块 → 返回
    |
    ├─ 检查 unsorted bin
    |   └─ 整理到对应的 bin
    |
    ├─ 使用 top chunk
    |   └─ 足够大 → 分割，返回
    |   └─ 不够 → 扩展堆（brk/mmap）
    |
    └─ 失败 → 返回 NULL
```

### 示例：malloc(32)

```c
void *ptr = malloc(32);
```

**内部过程**：
1. 请求大小：32 字节
2. 对齐到 8 的倍数：32
3. 加上头部大小（0x10）：42
4. 再次对齐：48 (0x30)
5. 查找合适的空闲块
6. 找到后返回用户数据指针（chunk + 0x10）

```
返回的指针 = chunk 地址 + 0x10
```

### 分配示例

```c
char *a = malloc(32);  // chunk A
char *b = malloc(32);  // chunk B
```

可能的内存布局：
```
Heap Start → 0x555555559000

Chunk A:
  0x555555559000:  prev_size = ?
  0x555555559008:  size = 0x31 (48字节 | PREV_INUSE)
  0x555555559010:  [用户数据开始 - a 指向这里]
  ...

Chunk B:
  0x555555559030:  prev_size = 0x30
  0x555555559038:  size = 0x31
  0x555555559040:  [用户数据开始 - b 指向这里]
  ...
```

**距离**：`b - a = 0x30` (48 字节)

---

## 堆溢出原理

### 什么是堆溢出？

堆溢出（Heap Overflow）是向堆分配的缓冲区写入超过其容量的数据，导致相邻内存被覆盖。

### 漏洞代码示例

```c
void *chunk1 = malloc(32);
void *chunk2 = malloc(32);

// 漏洞：读取 100 字节到 32 字节的缓冲区
read(0, chunk1, 100);  // ← 堆溢出！
```

### 内存布局分析

```
分配前:
  +------------------+
  |     未分配       |
  +------------------+

malloc(32) → chunk1:
  +------------------+  ← chunk1
  | metadata (0x10)  |
  +------------------+  ← chunk1 + 0x10 (返回地址)
  |   32 字节        |
  +------------------+

malloc(32) → chunk2:
  +------------------+  ← chunk2 (chunk1 + 0x30)
  | metadata (0x10)  |
  +------------------+  ← chunk2 + 0x10 (返回地址)
  |   32 字节        |
  +------------------+

正常写入 (32 字节):
  chunk1: [AAAAAAAA...] (32 字节)
  chunk2: [ untouched ]

溢出写入 (100 字节):
  chunk1: [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA] (32 字节)
          [BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB] (继续写入 32 字节)
  chunk2: [pwned!]                          ← chunk2 被覆盖！
```

### 为什么能溢出到 chunk2？

**原因 1**：连续分配通常在内存中相邻
```c
malloc(32);  // 从堆的当前位置分配
malloc(32);  // 紧接在后一个位置
```

**原因 2**：glibc malloc 的分配策略
- 小块分配从 top chunk 切割
- top chunk 通常在堆的末尾
- 相同大小的分配通常连续

### 溢出的影响

1. **数据泄露**：读取被覆盖的内存
2. **控制流劫持**：覆盖函数指针、返回地址
3. **元数据破坏**：破坏 chunk 的 size/fd/bk 字段
4. **UAF 触发**：覆盖指针导致 use-after-free

---

## 内存布局分析

### 实验代码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *a, *b, *c;

    a = malloc(32);
    b = malloc(32);
    c = malloc(32);

    printf("a: %p\n", a);
    printf("b: %p\n", b);
    printf("c: %p\n", c);

    printf("b - a: %ld (0x%lx)\n", b - a, b - a);
    printf("c - b: %ld (0x%lx)\n", c - b, c - b);

    return 0;
}
```

### 典型输出

```
a: 0x5555555592a0
b: 0x5555555592c0
c: 0x5555555592e0

b - a: 32 (0x20)
c - b: 32 (0x20)
```

**等等！为什么是 0x20 而不是 0x30？**

因为 `malloc()` 返回的是用户数据指针，不是 chunk 起始地址！

### 完整布局

```
Chunk A (完整大小 0x30):
  0x555555559290: [metadata: 0x00, 0x31]
  0x5555555592a0: [用户数据] ← a 指向这里

Chunk B (完整大小 0x30):
  0x5555555592c0: [metadata: 0x30, 0x31]
  0x5555555592d0: [用户数据] ← b 指向这里

Chunk C (完整大小 0x30):
  0x5555555592e0: [metadata: 0x30, 0x31]
  0x5555555592f0: [用户数据] ← c 指向这里
```

### 实际溢出

```python
# 从 a 覆盖到 b
payload = b"A" * 32  # 填满 a 的用户数据
payload += b"B" * 16  # 覆盖 b 的元数据
payload += b"C" * 8   # 覆盖 b 的用户数据开头
```

或者更简单地：
```python
payload = b"A" * 32 + b"pwned!"  # 直接覆盖 b 的内容
```

---

## 总结

### 关键要点

1. **Chunk 结构**：
   - 元数据：prev_size, size, fd, bk
   - 用户数据从 `chunk + 0x10` 开始
   - size 的最低 3 位是标志位

2. **分配过程**：
   - 请求大小 → 对齐 → 加头部 → 对齐
   - 从 bins 或 top chunk 获取
   - 返回用户数据指针

3. **堆溢出**：
   - 写入超过分配的大小
   - 覆盖相邻 chunk 的数据或元数据
   - 可导致数据泄露或控制流劫持

4. **内存布局**：
   - 相邻分配通常在内存中连续
   - 距离 = 对齐后的请求大小 + 0x10
   - 用户数据指针之间的距离 = 请求大小（对齐后）

### 下一步学习

现在你理解了堆溢出的原理，可以：
1. 完成 [Level 1 挑战](../README.md)
2. 阅读 [Level 1 Walkthrough](walkthrough.md)
3. 继续学习 [Level 2: Use-After-Free](../../level02_uaf/)

---

**记住**: 理论 + 实践 = 掌握！ 🎯
