# 环境配置详细指南

本文档详细说明如何配置堆漏洞利用的开发环境。

## 推荐方式：Docker（最简单）

### 安装 Docker

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker

# 将当前用户添加到 docker 组（避免 sudo）
sudo usermod -aG docker $USER
newgrp docker
```

#### macOS
```bash
brew install docker docker-compose
```

### 启动课程环境

```bash
# 克隆仓库
git clone <repository-url>
cd heap-mastery-course

# 启动容器
docker-compose up -d

# 进入容器
docker-compose exec course bash

# 在容器内构建
mkdir build && cd build
cmake ..
make

# 运行环境检查
./level00_setup/check_env
```

## 本地安装

### 系统：Ubuntu 22.04

#### 1. 基础工具

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc \
    g++ \
    gdb \
    git \
    vim \
    file \
    strace \
    ltrace \
    checksec
```

#### 2. Python 和 Pwntools

```bash
# Python 3 通常已安装
python3 --version  # 应该 >= 3.8

# 安装 Pwntools
pip3 install pwntools

# 验证
python3 -c "import pwn; print(pwn.__version__)"
```

#### 3. GDB 插件：Pwndbg

```bash
# 安装依赖
sudo apt-get install -y python3-dev

# 克隆并安装
cd ~
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# 验证
gdb -q
# 应该看到 pwndbg 启动信息
```

### 系统：macOS

#### 1. 安装 Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### 2. 安装工具

```bash
brew install gcc gdb python3

# 注意：macOS 的堆实现与 Linux 不同
# 建议使用 Docker 或 Linux 虚拟机
```

### 系统：Arch Linux

```bash
sudo pacman -S \
    base-devel \
    gcc \
    gdb \
    python \
    python-pwntools \
    checksec
```

## 验证安装

### 运行完整检查

```bash
cd heap-mastery-course
./tests/test_all_levels.sh
```

### 手动验证

#### GCC 版本
```bash
gcc --version
# 需要 >= 9.0
```

#### glibc 版本
```bash
ldd --version
# 推荐 2.27-2.35
```

#### GDB 和 Pwndbg
```bash
gdb -q
# 应该看到：pwndbg: loaded ...
quit
```

#### Pwntools
```bash
python3 -c "from pwn import *; print('OK')"
```

## 可选工具

### GEF (GDB Enhanced Features)

```bash
# GEF 是另一个 GDB 插件
bash -c "$(curl -fsSL https://gef.blah.cat.sh)"
```

### 其他工具

```bash
# ROPgadget - 寻找 ROP gadgets
pip3 install ROPgadget

# one_gadget - one_gadget RCE
pip3 install one_gadget

# patchelf - 修改 ELF
sudo apt-get install patchelf
```

## 环境变量

### 推荐设置

添加到 `~/.bashrc` 或 `~/.zshrc`：

```bash
# GDB 配置
export GDK_BACKEND=x11

# Pwntools 默认设置
export PWNLIB_NOTERM=1

# 调试符号
export DEBUG=1
```

## 常见问题

### Q: Pwndbg 无法加载？

A: 确保 GDB 版本兼容：
```bash
gdb --version  # 需要 >= 8.0

# 重新安装 Pwndbg
cd ~/pwndbg
./setup.sh --update
```

### Q: Pwntools 导入失败？

A: 检查 Python 版本：
```bash
python3 --version  # 需要 >= 3.8

# 重新安装
pip3 install --upgrade pwntools
```

### Q: 编译错误？

A: 检查 GCC 版本和标志：
```bash
gcc --version

# 手动编译测试
echo 'int main(){return 0;}' | gcc -x c - -o test
```

### Q: Docker 容器无法访问？

A: 检查容器状态：
```bash
docker-compose ps
docker-compose logs
```

## glibc 版本管理

不同的 glibc 版本可能影响堆利用技术。

### 检查当前版本

```bash
ldd --version
# 或
strings /lib/x86_64-linux-gnu/libc.so.6 | grep GLIBC
```

### 切换版本（高级）

使用 `glibc-all-in-one`：
```bash
# 安装
git clone https://github.com/matrix1001/glibc-all-in-one
cd glibc-all-in-one
./update_list
./download <version>

# 使用
./compile <version>
```

## 性能优化

### SSD 存储

将项目放在 SSD 上提高编译速度。

### ccache

```bash
sudo apt-get install ccache
# CMake 会自动检测
```

### 并行编译

```bash
make -j$(nproc)
```

## 下一步

环境配置完成后：

1. 运行 [Level 0 环境检查](../level00_setup/)
2. 阅读 [调试工具指南](03_debugging_tools.md)
3. 开始 [Level 1](../level01_overflow/)

---

**环境配置完成后，你就可以开始学习了！** 🚀
