# Level 0: 环境配置与基础

欢迎来到堆精通课程！在这一关，我们将配置好所有必要的环境，并学习堆的基础知识。

## 学习目标

完成本关后，你将：
- ✅ 配置好完整的堆漏洞利用开发环境
- ✅ 理解堆和栈的区别
- ✅ 掌握基本的 malloc/free 操作
- ✅ 学会使用 GDB 和 Pwndbg 调试堆

## 环境检查

首先运行环境检查程序：

```bash
cd build
./level00_setup/check_env
```

如果所有检查都通过，你会看到绿色的 "✓ All checks passed!" 消息。

如果有任何检查失败，请按照下方的说明进行修复。

## 环境配置

### 方法1: 使用 Docker（推荐）

```bash
# 启动 Docker 容器
docker-compose up -d

# 进入容器
docker-compose exec course bash

# 在容器内
cd build
cmake ..
make
./level00_setup/check_env
```

### 方法2: 本地安装

#### 1. 安装 GCC

```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc g++
```

验证安装：
```bash
gcc --version  # 应该是 9.0 或更高版本
```

#### 2. 安装 GDB 和 Pwndbg

```bash
# 安装 GDB
sudo apt-get install -y gdb

# 安装 Pwndbg（推荐）
cd ~
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

验证安装：
```bash
gdb -q  # 应该看到 pwndbg 启动信息
```

#### 3. 安装 Python 和 Pwntools

```bash
# Python3 通常已经安装
python3 --version

# 安装 Pwntools
pip3 install pwntools
```

验证安装：
```bash
python3 -c "import pwn; print(pwn.__version__)"
```

#### 4. 安装其他工具

```bash
sudo apt-get install -y \
    checksec \
    file \
    strace \
    ltrace \
    libc6-dbg
```

## 堆的基础知识

### 堆 vs 栈

| 特性 | 栈 (Stack) | 堆 (Heap) |
|------|-----------|----------|
| 分配方式 | 自动（函数调用） | 手动（malloc/free） |
| 分配大小 | 编译时确定 | 运行时确定 |
| 生命周期 | 函数作用域 | 程序员控制 |
| 分配速度 | 快（移动指针） | 较慢（查找空闲块） |
| 地址方向 | 从高到低 | 从低到高 |

### 基本的堆操作

```c
#include <stdlib.h>

// 分配内存
void *ptr = malloc(size);  // size 是字节数
if (ptr == NULL) {
    // 分配失败
}

// 使用内存
// ...

// 释放内存
free(ptr);
ptr = NULL;  // 好习惯：释放后置空
```

### 堆的内部结构（简化）

```
+----------------+
| Chunk Metadata |  <- size, prev_size, flags
+----------------+
| User Data      |  <- 你可以使用的内存
| ...            |
+----------------+
```

每个堆块（chunk）包含：
- **size 字段**: 块大小（包括元数据）
- **prev_size**: 前一个块的大小（如果前一个块空闲）
- **标志位**:
  - PREV_INUSE (0x1): 前一个块是否在使用中
  - IS_MMAPPED (0x2): 是否通过 mmap 分配
  - NON_MAIN_ARENA (0x4): 是否在非主分配区

## 使用 GDB 调试堆

### 基础 GDB 命令

```bash
# 启动 GDB
gdb ./vuln

# 设置断点
(gdb) break main
(gdb) break malloc

# 运行程序
(gdb) run

# 单步执行
(gdb) next    # 下一行（不进入函数）
(gdb) step    # 下一行（进入函数）

# 查看内存
(gdb) x/10x $rsp    # 查看栈
(gdb) x/10x 0x5555  # 查看特定地址

# 继续执行
(gdb) continue
```

### Pwndbg 堆命令（推荐）

Pwndbg 提供了强大的堆调试功能：

```bash
# 查看堆布局
(gdb) heap           # 显示所有 chunks
(gdb) arenas         # 显示分配区信息

# 查看 fastbins
(gdb) fastbins       # 显示 fastbin 链表

# 查看 tcache
(gdb) tcache         # 显示 tcache

# 查看特定 chunk
(gdb) heap_chunk 0x5555  # 查看指定地址的 chunk

# 搜索堆
(gdb) search -t dword 0x41414141  # 搜索特定值
```

## 练习：创建你的第一个堆程序

创建文件 `myheap.c`：

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("=== 堆操作练习 ===\n\n");

    // 1. 分配一个 chunk
    void *ptr1 = malloc(32);
    printf("1. malloc(32) = %p\n", ptr1);

    // 2. 分配另一个 chunk
    void *ptr2 = malloc(64);
    printf("2. malloc(64) = %p\n", ptr2);

    // 3. 使用 chunk
    sprintf(ptr1, "Hello, Heap!");
    printf("3. ptr1 content: %s\n", (char *)ptr1);

    // 4. 释放 chunk
    free(ptr1);
    printf("4. freed ptr1\n");

    // 5. 再次分配（可能重用刚才释放的内存）
    void *ptr3 = malloc(32);
    printf("5. malloc(32) = %p (reused?)\n", ptr3);

    // 清理
    free(ptr2);
    free(ptr3);

    return 0;
}
```

编译并运行：
```bash
gcc -g -o myheap myheap.c
./myheap
```

用 GDB 调试：
```bash
gdb ./myheap
```

在 GDB 中：
```
(gdb) break main
(gdb) run
(gdb) heap          # 查看堆
(gdb) next          # 执行到下一个 malloc
(gdb) heap          # 再次查看堆
```

## 常见问题

### Q: Pwndbg 无法启动？

A: 确保 GDB 版本兼容，重新安装：
```bash
cd ~/pwndbg
./setup.sh --update
```

### Q: malloc 返回 NULL？

A: 可能是内存不足或堆损坏。检查：
- 是否有堆溢出
- 是否 double-free
- 使用 GDB 查看 heap 状态

### Q: 如何查看 glibc 版本？

A: 运行：
```bash
ldd --version
# 或
strings /lib/x86_64-linux-gnu/libc.so.6 | grep GLIBC
```

## 下一步

环境配置完成后，你准备好进入 **[Level 1: 堆溢出基础](../level01_overflow/)** 了！

在下一关，你将：
- 学习堆 chunk 的详细结构
- 理解堆缓冲区溢出
- 编写你的第一个堆漏洞利用程序

## 参考资源

- [GDB 官方文档](https://www.gnu.org/software/gdb/documentation/)
- [Pwndbg GitHub](https://github.com/pwndbg/pwndbg)
- [Pwntools 文档](https://docs.pwntools.com/)
- [GLIBC Malloc 源码](https://sourceware.org/git/?p=glibc.git;a=tree;f=malloc)

---

**准备好挑战了吗？继续下一关！** 🚀
