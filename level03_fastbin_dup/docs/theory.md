# Level 3: Fastbin Double Free - 理论详解

## 目录
1. [什么是 Fastbin?](#什么是-fastbin)
2. [Fastbin 工作原理](#fastbin-工作原理)
3. [Double Free 漏洞](#double-free-漏洞)
4. [Fastbin Double Free 攻击](#fastbin-double-free-攻击)
5. [安全机制与绕过](#安全机制与绕过)

---

## 什么是 Fastbin?

### Fastbin 简介

**Fastbin** 是 glibc malloc 中用于管理小内存块的快速分配机制。

- **大小范围**: 通常 16~80 字节 (根据架构和版本)
- **数据结构**: 单链表 (LIFO - 后进先出)
- **位置**: 在 malloc_state 中直接存储
- **性能**: 最快的分配/释放路径

### Fastbin vs 其他 Bins

| Bin 类型 | 大小范围 | 数据结构 | 性能 |
|---------|---------|---------|------|
| **Tcache** | 小块 | 单链表 (per-thread) | 最快 |
| **Fastbin** | 小块 | 单链表 | 很快 |
| **Small bin** | 中等 | 双链表 (FIFO) | 中等 |
| **Large bin** | 大块 | 双链表 (排序) | 较慢 |
| **Unsorted bin** | 任意 | 双链表 | 中转站 |

### Fastbin 链表结构

```
Fastbin[Y] (size = 0x20)
    ↓
+-----------+-------+-----------+
| prev_size | 0x21  | fd        | ← Chunk A
+-----------+-------+-----------+
                  ↓
+-----------+-------+-----------+
| prev_size | 0x21  | fd        | ← Chunk B
+-----------+-------+-----------+
                  ↓
                 NULL
```

---

## Fastbin 工作原理

### 分配 (malloc)

```c
void* malloc(size_t size) {
    // 1. 检查 tcache (glibc 2.26+)
    // 2. 检查对应的 fastbin
    int idx = fastbin_index(size);

    if (fastbin(idx)->fd != NULL) {
        // LIFO: 取链表头部
        chunk = fastbin(idx)->fd;
        fastbin(idx)->fd = chunk->fd;
        return chunk2mem(chunk);
    }

    // 3. 没有空闲块，从 top chunk 分配
    // ...
}
```

### 释放 (free)

```c
void free(void* mem) {
    chunk = mem2chunk(mem);

    // 检查大小是否在 fastbin 范围
    if (size <= FASTBIN_MAX_SIZE) {
        int idx = fastbin_index(size);

        // 检查 double free (基本检测)
        if (chunk == fastbin(idx)->fd) {
            // 可能是 double free!
            // 但不是所有情况都能检测到
        }

        // LIFO: 插入链表头部
        chunk->fd = fastbin(idx)->fd;
        fastbin(idx)->fd = chunk;
        return;
    }

    // 进入 small/large/unsorted bin
    // ...
}
```

### 关键特性

1. **LIFO (后进先出)**: 最后释放的块最先被分配
2. **不合并**: fastbin 中的块不会与相邻块合并
3. **单线程**: fastbin 操作不加锁 (main arena 除外)
4. **fd 指针**: 空闲时，fd 指针指向下一个空闲块

---

## Double Free 漏洞

### 什么是 Double Free?

**Double Free** 指对同一块内存释放两次：

```c
char *ptr = malloc(32);
free(ptr);
free(ptr);  // ← Double Free!
```

### 为什么危险?

Double Free 可以让我们：
1. **操纵 fastbin 链表**: 控制空闲块的链表结构
2. **分配到任意地址**: 通过伪造 fd 指针
3. **实现任意地址写**: 后续 malloc 可返回目标地址

### 基本检测机制

glibc 有基本的 double free 检测：

```c
// 检查: 如果 chunk 已经在 fastbin 链表头部
if (chunk == fastbin(idx)) {
    malloc_printerr("double free");
    return;
}
```

**问题**: 这个检测很弱！只检测链表头部。

---

## Fastbin Double Free 攻击

### 攻击原理

通过 double free，我们可以在 fastbin 链表中插入重复的 chunk：

```
初始状态:
fastbin[0x20] → NULL

步骤 1: malloc A = malloc(32)
步骤 2: free(A)
fastbin[0x20] → A → NULL

步骤 3: malloc B (不同地址)
步骤 4: free(B)
fastbin[0x20] → B → A → NULL

步骤 5: free(A)  ← Double Free!
fastbin[0x20] → A → B → A → NULL
              └─────────┘
               形成循环!
```

### 利用步骤

#### 1. 创建循环链表

```python
# 分配 3 个 chunk
a = malloc(32)  # chunk A
b = malloc(32)  # chunk B (防止合并)
c = malloc(32)  # chunk C

# 释放 A (进入 fastbin)
free(a)

# 释放 C (进入 fastbin)
free(c)

# Double Free A!
free(a)  # ← 漏洞点!
```

```
fastbin[0x20] → A → C → A → ...
                  └────────┘
                    循环!
```

#### 2. 修改 fd 指针

```python
# 分配 A (从 fastbin 移除)
a2 = malloc(32)  # 返回 A

# 现在可以编辑 A，实际上是编辑 fastbin 链表!
# A 的 fd 指针现在是链表的一部分
# 修改 A 的 fd 为目标地址
fake_chunk = target_address - 0x10
edit(a2, p64(fake_chunk))
```

```
fastbin[0x20] → C → A → fake_chunk → NULL
                  │
              已被修改!
```

#### 3. 分配到目标地址

```python
# 分配 C (从 fastbin 移除)
c2 = malloc(32)

# 分配 A (从 fastbin 移除)
a3 = malloc(32)

# 下一次分配返回 fake_chunk!
target = malloc(32)  # ← 返回 target_address!
```

---

## 安全机制与绕过

### 1. 基本检测 (glibc < 2.26)

```c
if (chunk == fastbin(idx)) {
    // double free detected
}
```

**绕过**: 在中间插入其他 chunk
```
A → B → A → ...
```

### 2. Tcache Double Free 检测 (glibc 2.26+)

glibc 2.26 引入 tcache，并添加了更强的检测：

```c
// tcache 有一个 eCount (entry count)
// 每个 chunk 最多 7 次
if (eCount >= mp_.tcache_count) {
    malloc_printerr("double free");
}
```

**绕过**: 填满 tcache (7次)，让第 8 次进入 fastbin

### 3. Safe Linking (glibc 2.32+)

glibc 2.32 引入 Safe Linking，对 fd 指针加密：

```c
fd = L >> 12  // 右移 12 位
fd = fd ^ P  // XOR heap 地址
```

**绕过**: 需要 heap 地址泄露或部分覆盖

---

## 实战示例

### 场景

程序允许：
- 分配 chunk
- 释放 chunk
- 编辑 chunk
- **漏洞**: free 后不置空指针

### Exploit 策略

```python
from pwn import *

# 1. 分配 3 个 chunk
chunk0 = alloc(32)
chunk1 = alloc(32)  # 防止 top chunk 合并
chunk2 = alloc(32)

# 2. 创建 double free 条件
free(chunk0)
free(chunk2)
free(chunk0)  # Double free!

# 3. 修改 fd 指针
alloc(32)  # 拿回 chunk0
target = 0xdeadbeef  # 目标地址
payload = p64(target - 0x10)
edit(chunk0, payload)

# 4. 分配到目标地址
alloc(32)  # chunk2
alloc(32)  # chunk0
fake_chunk = alloc(32)  # ← 返回 target-0x10+0x10!

# 5. 写入目标地址
edit(fake_chunk, p64(0x4141414141414141))
```

---

## 防御措施

### 编程层面

```c
// ✓ 正确做法
free(ptr);
ptr = NULL;  // 立即置空!

// ✗ 错误做法
free(ptr);
// ptr 仍是野指针
```

### 编译保护

```bash
# 使用现代 glibc (2.32+)
# 启用 Safe Linking

# 使用 Address Sanitizer
gcc -fsanitize=address vuln.c -o vuln
```

### 运行时检测

```bash
# 设置 MALLOC_CHECK_
export MALLOC_CHECK_=1  # 报告错误
export MALLOC_CHECK_=2  # 中止程序

# 使用 MALLOC_DEBUG_
export MALLOC_DEBUG_=1
```

---

## 相关技术

- **Tcache Poisoning**: 类似技术，针对 tcache
- **Unsafe Unlink**: 攻击 small/large bin
- **House of Spirit**: 伪造 fastbin chunk
- **Fastbin Attack into Stack**: 分配到栈上

---

## 参考资料

- [How2Heap: fastbin_dup](https://github.com/shellphish/how2heap#glibc-fastbin-dup)
- [How2Heap: fastbin_dup_into_stack](https://github.com/shellphish/how2heap#glibc-fastbin-dup-into-stack)
- [glibc Malloc Source Code](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c)
- [CTF Wiki: Fastbin Attack](https://ctf-wiki.org/pwn/linux/glibc-heap/fastbin_attack/)

---

## 关键要点

1. ✅ Fastbin 使用 LIFO 单链表
2. ✅ Double Free 可以创建循环链表
3. ✅ 通过修改 fd 指针实现任意地址分配
4. ✅ 现代保护 (Safe Linking) 需要额外技术绕过
5. ✅ 关键：理解链表操作和指针操纵

**下一步**: 实践 Level 3 挑战!
