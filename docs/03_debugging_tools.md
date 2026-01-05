# 调试工具指南

学习堆漏洞利用需要熟练使用调试工具。本文档详细介绍 GDB、Pwndbg 和 Pwntools。

## GDB 基础

### 启动 GDB

```bash
# 调试可执行文件
gdb ./vuln

# 附加到运行中的进程
gdb -p <PID>

# 使用 core dump
gdb ./vuln core
```

### 常用命令

```
# 运行控制
(gdb) run [args]      # 运行程序
(gdb) continue        # 继续执行
(gdb) next            # 单步（不进入函数）
(gdb) step            # 单步（进入函数）
(gdb) finish          # 完成当前函数
(gdb) kill            # 终止程序
(gdb) quit            # 退出 GDB

# 断点
(gdb) break main      # 在函数设置断点
(gdb) break *0x400500 # 在地址设置断点
(gdb) delete 1        # 删除断点 1
(gdb) info breakpoints # 列出所有断点

# 信息查看
(gdb) backtrace       # 调用栈
(gdb) frame 0         # 切换栈帧
(gdb) info registers  # 寄存器
(gdb) info func       # 函数列表
(gdb) disassemble     # 反汇编
```

### 内存检查

```
# 查看内存
(gdb) x/10x $rsp              # 10 个十六进制数
(gdb) x/20i 0x400500          # 20 条指令
(gdb) x/s $rax                # 字符串
(gdb) x/g 0x55555555          # 8 字节 Giants

# 搜索内存
(gdb) find $rsp, $rsp+100, 0x41414141
```

## Pwndbg

Pwndbg 是专门为漏洞利用设计的 GDB 插件。

### 堆相关命令

```
# 堆布局
(gdb) heap                   # 显示所有 chunks
(gdb) arenas                 # 显示分配区
(gdb) top_chunk              # 显示 top chunk
(gdb) main_arena             # 显示 main arena

# Bins
(gdb) fastbins               # Fastbin 链表
(gdb) tcache                 # Tcache 状态
(gdb) smallbins              # Small bin
(gdb) largebins              # Large bin
(gdb) unsortedbin            # Unsorted bin
(gdb) bins                   # 所有 bins

# Chunk 信息
(gdb) heap_chunk <addr>      # 显示特定 chunk
(gdb) chunk_pointer <addr>   # 显示 chunk 指针

# 分配跟踪
(gdb) allocs                 # 所有分配
(gdb) frees                  # 所有释放
(gdb) bins                   # Bin 状态
```

### 实用功能

```
# 地址转换
(gdb) telescope $rsp 8       # 显示 8 个指针

# 搜索
(gdb) search -t dword 0x41414141  # 搜索 4 字节

# 模式
(gdb) aslr                   # 显示 ASLR 状态
(gdb) checksec               # 检查二进制保护

# 信息
(gdb) libc                   # 显示 libc 基址
(gdb) code-base              # 代码基址
(gdb) heap-base              # 堆基址
```

### 典型调试流程

```bash
# 1. 启动调试
gdb ./vuln

# 2. 设置断点
(gdb) break main
(gdb) break malloc
(gdb) break free

# 3. 运行
(gdb) run

# 4. 在 malloc 后检查堆
(gdb) continue
(gdb) heap

# 5. 查看特定 chunk
(gdb) heap_chunk 0x55555555

# 6. 单步执行
(gdb) next

# 7. 查看内存
(gdb) telescope $rsp 10
```

## Pwntools

Pwntools 是 Python 的漏洞利用框架。

### 基本使用

```python
from pwn import *

# 连接
p = process('./vuln')         # 本地
p = remote('host', 1234)      # 远程

# 发送接收
p.sendline(b'payload')
data = p.recv(1024)
p.interactive()
```

### ELF 操作

```python
elf = ELF('./vuln')

# 符号和地址
main_addr = elf.symbols['main']
plt_puts = elf.plt['puts']
got_puts = elf.got['puts']

# 检查保护
print(elf.checksec())
```

### ROP 链

```python
from pwn import *

# ROP gadget
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.main()

print(rop.dump())
```

### 内存操作

```python
# flat() - 展平嵌套列表
payload = flat([
    b'A' * 32,
    p64(0xdeadbeef),
])

# cyclic() - 生成模式
pattern = cyclic(100)
offset = cyclic_find(0x61616162)  # 查找偏移

# p32/p64 - 打包
addr = p64(0xdeadbeefcafebabefull)

# u32/u64 - 解包
value = u64(data[:8])
```

### 完整模板

```python
#!/usr/bin/env python3
from pwn import *

# 配置
context.log_level = 'debug'
context.binary = './vuln'

# 启动进程
p = process('./vuln')

# 或附加 GDB
p = process('./vuln')
gdb.attach(p, '''
    break main
    continue
''')

# 构建 payload
payload = flat([
    b'A' * 32,
    p64(0xdeadbeef),
])

# 发送
p.sendline(payload)

# 接收
response = p.recvall()
print(response)

# 交互
p.interactive()
```

## 组合使用

### 典型工作流程

1. **静态分析**：用 objdump/IDA 查看二进制
2. **动态调试**：用 Pwndbg 观察运行时行为
3. **利用开发**：用 Pwntools 编写脚本
4. **验证测试**：结合 GDB 调试脚本

### 示例：调试利用脚本

```python
from pwn import *

# 启动程序
p = process('./vuln')

# 附加 GDB
gdb.attach(p, '''
    break *0x401234
    heap
    continue
''')

# 发送 payload
payload = cyclic(100)
p.sendline(payload)

# 检查崩溃
p.wait()
```

## 高级技巧

### 条件断点

```
(gdb) break malloc if $rdi == 32
```

### 命令脚本

```
(gdb) define hook-stop
  echo $rip:
  x/i $rip
  end
```

### Python 脚本

```python
# gdb_commands.py
gdb.execute('break main')
gdb.execute('run')
```

```bash
gdb -x gdb_commands.py ./vuln
```

## 推荐工作流

1. **初步分析**
   ```bash
   checksec ./vuln
   objdump -d ./vuln | less
   ```

2. **调试运行**
   ```bash
   gdb ./vuln
   (gdb) break main
   (gdb) run
   ```

3. **堆分析**
   ```
   (gdb) heap
   (gdb) fastbins
   ```

4. **利用开发**
   ```python
   # exploit.py
   from pwn import *
   # ... 开发利用 ...
   ```

5. **验证调试**
   ```python
   gdb.attach(p, 'heap')
   p.interactive()
   ```

## 学习资源

- [GDB 官方文档](https://www.gnu.org/software/gdb/documentation/)
- [Pwndbg GitHub](https://github.com/pwndbg/pwndbg)
- [Pwntools 文档](https://docs.pwntools.com/)
- [CTF Wiki - PWN](https://ctf-wiki.org/pwn/linux/user-mode/pwn-tools/introduction/)

---

**熟练掌握这些工具是堆漏洞利用的基础！** 🛠️
