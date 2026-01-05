# Level 7: Advanced Techniques - 提示

<details>
<summary><b>提示 1: 理解高级挑战</b></summary>

**Level 7 是什么？**

这是**终极挑战**，综合运用所有技术：
- Safe Linking 绕过 (glibc 2.32+)
- 复杂的堆布局
- 信息泄露
- 函数指针劫持

**前置要求**：
- ✅ 完成前面所有关卡
- ✅ 理解 fastbin/tcache 攻击
- ✅ 理解堆风水
- ✅ 了解 Safe Linking

**难度**：⭐⭐⭐⭐⭐⭐ (专家级)

**预计时间**：6-10 小时
</details>

<details>
<summary><b>提示 2: 程序分析</b></summary>

首先阅读源代码：

```bash
cat level07_advanced/challenge/vuln.c
```

**关键点**：
1. 找到漏洞点
2. 理解胜利条件
3. 识别可用的原语
4. 确定需要的攻击步骤

**查找**：
- malloc/free 调用
- 用户输入处理
- 指针操作
- 函数指针
```
</details>

<details>
<summary><b>提示 3: Safe Linking 原理</b></summary>

**Safe Linking** (glibc 2.32+) 保护 fastbin/tcache：

```c
// fd 指针加密
fd = L >> 12        // L 是目标地址右移 12 位
fd = fd ^ P         // P 是堆地址
```

**为什么需要绕过**？
- 现代系统默认启用
- 不能直接伪造 fd 指针
- 需要泄露地址或使用部分覆盖

**检测你的 glibc 版本**：
```bash
ldd --version
```
</details>

<details>
<summary><b>提示 4: 攻击策略概述</b></summary>

典型的高级攻击流程：

```
1. 信息泄露阶段
   ├─ 泄露堆地址
   ├─ 泄露 libc 地址（如需要）
   └─ 计算 Safe Linking key

2. 布局控制阶段
   ├─ 使用堆风水技巧
   ├─ 创造 overlap 或 UAF
   └─ 准备目标对象

3. 指针操纵阶段
   ├─ 绕过 Safe Linking
   ├─ 修改 fd/bk 指针
   └─ 控制分配流程

4. 利用阶段
   ├─ 分配到目标地址
   ├─ 修改关键数据结构
   └─ 触发胜利条件
```
</details>

<details>
<summary><b>提示 5: 信息泄露技术</b></summary>

**方法 1: 利用 UAF 泄露**
```python
# 释放一个包含指针的 chunk
free(chunk_with_pointer)

# 重新分配并读取
new_chunk = alloc(size)
data = read(new_chunk)

# 从 data 中提取地址
heap_addr = u64(data[:8])
```

**方法 2: 利用 unsorted bin**
```python
# unsorted bin 的 fd/bk 指向 libc
free(large_chunk)

# 读取 fd/bk
libc_addr = read(fd) - offset
```

**方法 3: 利用打印功能**
```python
# 如果程序有打印功能
print(chunk)  # 可能泄露地址
```
</details>

<details>
<summary><b>提示 6: Safe Linking 绕过</b></summary>

**方法 1: 部分覆盖**
```python
# 只修改低 12 位（Safe Linking 不影响的部分）
# 适用于目标地址在同一堆区域

original = 0x55555555a000  # 原始地址
target  = 0x55555555b000   # 目标地址

# 只需要修改少量字节
# 例如：修改 0xa000 → 0xb000
payload = p16(0xb000)  # 只覆盖低 2 字节
```

**方法 2: 完整计算**
```python
# 如果泄露了堆地址
heap_base = 0x555555550000
chunk_addr = 0x55555555a000

# 计算 Safe Linking fd
target = 0x55555555b000
L = target >> 12
P = chunk_addr
fd = L ^ P

edit(chunk, p64(fd))
```
</details>

<details>
<summary><b>提示 7: House of Einherjar</b></summary>

这是绕过 Safe Linking 的经典技术：

**原理**：
- 利用 chunk 的 `prev_size` 字段
- 配合 `PREV_INUSE` 标志
- 实现向后合并

**步骤**：
```
1. 伪造 chunk 的 prev_size
2. 清除下一个 chunk 的 PREV_INUSE
3. 释放，触发合并
4. 新的大 chunk 包含目标地址
```

**适用场景**：
- glibc 2.32+
- 需要精确控制布局
- 需要分配到特定地址
</details>

<details>
<summary><b>提示 8: 实战步骤 - 第一阶段</b></summary>

```python
from pwn import *

p = process('./vuln')
context.log_level = 'info'

# 定义基本操作
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

# 步骤 1: 分配一些 chunk
alloc(32)  # 0
alloc(32)  # 1
alloc(64)  # 2 - 用于泄露

# 步骤 2: 尝试泄露
free(2)
alloc(64)  # 3 - 可能重用 chunk[2]

# 步骤 3: 检查是否有泄露
# 查看输出或打印功能
```
</details>

<details>
<summary><b>提示 9: 实战步骤 - 第二阶段</b></summary>

```python
# 假设已泄露堆地址
heap_leak = 0x55555555a000  # 示例

# 计算目标
target = heap_leak + 0x500  # 示例偏移

# 创造 double free (需要绕过检测)
alloc(32)  # 4
alloc(32)  # 5
alloc(32)  # 6

free(4)
free(6)
free(4)  # double free

# 现在修改 fd (考虑 Safe Linking)
# 如果 glibc < 2.32: 直接伪造
# 如果 glibc >= 2.32: 需要计算或部分覆盖
```
</details>

<details>
<summary><b>提示 10: 完整 Exploit 框架</b></summary>

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
p = process('./vuln')

# ... 定义 alloc, free, edit ...

def exploit():
    # 阶段 1: 信息泄露
    log.info("阶段 1: 信息泄露")
    # ... 泄露代码 ...

    # 阶段 2: 布局控制
    log.info("阶段 2: 布局控制")
    # ... 堆风水 ...

    # 阶段 3: 指针操纵
    log.info("阶段 3: 指针操纵")
    # ... 绕过 Safe Linking ...

    # 阶段 4: 触发胜利
    log.info("阶段 4: 触发胜利")
    # ... 最终利用 ...

exploit()
p.interactive()
```
</details>

<details>
<summary><b>提示 11: 调试技巧</b></summary>

**使用 GDB + Pwndbg**：

```bash
# 查看堆布局
(gdb) heap

# 查看 tcache/fastbin
(gdb) tcache
(gdb) fastbin

# 查看 Safe Linking
(gdb) x/gx chunk_address
# 手动计算: (fd >> 12) ^ heap_address

# 断点在关键位置
(gdb) b *malloc+XXX
(gdb) b *free+XXX
```

**使用 Python 脚本辅助**：
```python
# 计算 Safe Linking fd
def calc_fd(target, heap_addr):
    return ((target >> 12) ^ heap_addr)

# 验证
fd = calc_fd(0x55555555b000, 0x55555555a000)
print(f"fd = {hex(fd)}")
```
</details>

<details>
<summary><b>提示 12: 常见问题</b></summary>

**问题 1**: "malloc(): invalid pointer"
- 原因：fd 指针错误（Safe Linking）
- 解决：正确计算 fd 或使用部分覆盖

**问题 2**: "double free or corruption"
- 原因：double free 检测更严格
- 解决：使用更复杂的绕过方法

**问题 3**: "tcache pointer mismatch"
- 原因：tcache key 检测失败
- 解决：泄露 tcache_key 或避免 tcache

**问题 4**: 无法泄露地址
- 原因：程序没有明显的泄露点
- 解决：创造 UAF 或 overlap
</details>

<details>
<summary><b>提示 13: 参考资源</b></summary>

**必读资源**：

1. **how2heap** - 最新技术
   ```
   https://github.com/shellphish/how2heap
   ```
   查看：
   - safe_linking.c
   - house_of_einherjar.c
   - tcache_poisoning.c

2. **CTF Wiki** - 详细教程
   ```
   https://ctf-wiki.org/pwn/linux/glibc-heap/
   ```

3. **glibc 源码** - 理解保护机制
   ```
   https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c
   ```

4. **CTF Writeups** - 实战经验
   - 搜索 "glibc 2.34 heap pwn"
   - 学习真实题目的解法
</details>

<details>
<summary><b>提示 14: 学习建议</b></summary>

**如何攻克这关？**

1. **先降级**
   ```bash
   # 修改 glibc 版本（如果可能）
   # 或在旧环境上测试
   ```

2. **分步实践**
   - 先完成信息泄露
   - 再完成指针操纵
   - 最后组合起来

3. **参考类似题目**
   - CTF Pwn 题
   - how2heap 示例

4. **耐心调试**
   - 使用 GDB
   - 打印中间状态
   - 理解每一步

5. **寻求帮助**
   - 查看论坛
   - 阅读 writeup
   - 请教他人
</details>

<details>
<summary><b>提示 15: 成功标志</b></summary>

完成这关后，你应该：

✅ **理解 Safe Linking**
   - 如何加密 fd 指针
   - 如何绕过保护

✅ **掌握高级技术**
   - 信息泄露
   - 地址计算
   - 复杂布局

✅ **实战能力**
   - 分析真实漏洞
   - 编写完整 exploit
   - 对抗现代保护

**恭喜！你已经达到了堆利用的高级水平！** 🎉
</details>
