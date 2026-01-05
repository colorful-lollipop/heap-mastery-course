# 堆精通课程 (Heap Mastery Course)

> 从零开始学习堆漏洞利用技术 - 包含堆喷、堆风水等高级技巧

[![License: MIT](https://img.shields.io/badge/License-Educational%20Use%20Only-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)](https://www.linux.org/)
[![GCC](https://img.shields.io/badge/gcc-9.0+-brightgreen.svg)](https://gcc.gnu.org/)

## 项目简介

这是一个全面的堆漏洞利用教学项目，专为安全入门人员、CTF选手和安全研究人员设计。通过**7个难度递增的关卡**，你将从基础的堆操作逐步掌握高级的堆喷和堆风水技术。

### 核心特性

- ✅ **7个渐进式关卡** - 从基础到专家的平滑过渡
- ✅ **手把手教学** - 每关配有详细的原理文档和利用指南
- ✅ **实战漏洞程序** - 精心设计的教学用漏洞程序
- ✅ **完整解法** - 提供Python和C语言的利用代码
- ✅ **提示系统** - 卡关时可查看渐进式提示
- ✅ **Docker环境** - 一键启动隔离的练习环境
- ✅ **自动化测试** - 验证所有关卡和利用代码
- ✅ **现代技术** - 涵盖Safe Linking、Tcache等2024-2025最新技术

## 关卡概览

| 关卡 | 主题 | 难度 | 预计时间 | 核心技术 |
|------|------|------|----------|----------|
| [Level 0](level00_setup/) | 环境配置与基础 | ⭐ | 1小时 | GDB、Pwndbg、堆基础 |
| [Level 1](level01_overflow/) | 堆溢出基础 | ⭐ | 2小时 | Chunk结构、堆元数据损坏 |
| [Level 2](level02_uaf/) | Use-After-Free | ⭐⭐ | 3小时 | UAF、堆重用、Dangling指针 |
| [Level 3](level03_fastbin_dup/) | Fastbin Double Free | ⭐⭐⭐ | 4小时 | Fastbin操作、双重释放 |
| [Level 4](level04_tcache/) | Tcache Poisoning | ⭐⭐⭐ | 4小时 | Tcache机制、现代堆利用 |
| [Level 5](level05_heap_spray/) | 堆喷技术 | ⭐⭐⭐⭐ | 6小时 | 堆喷射、内存布局控制 |
| [Level 6](level06_feng_shui/) | 堆风水 | ⭐⭐⭐⭐⭐ | 8小时 | 精确堆布局、多bin协调 |
| [Level 7](level07_advanced/) | 高级技术与绕过 | ⭐⭐⭐⭐⭐+ | 12小时 | Safe Linking、House系列 |

## 快速开始

### 方式1: Docker (推荐)

```bash
# 克隆仓库
git clone https://github.com/yourusername/heap-mastery-course.git
cd heap-mastery-course

# 启动Docker环境
docker-compose up -d

# 进入容器
docker-compose exec course bash

# 构建所有关卡
mkdir build && cd build
cmake ..
make

# 测试环境配置
./level00_setup/check_env
```

### 方式2: 本地安装

```bash
# 安装依赖
sudo apt-get update
sudo apt-get install -y build-essential gcc gdb python3 python3-pip

# 安装Pwntools
pip3 install pwntools

# 安装Pwndbg (推荐)
cd ~
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# 构建项目
mkdir build && cd build
cmake ..
make
```

## 学习路径

1. **从Level 0开始** - 配置好你的调试环境
2. **按顺序学习** - 每关依赖前一关的知识
3. **阅读文档** - 先理解原理，再动手实践
4. **利用提示** - 卡关时查看hints.md
5. **研究解法** - 完成后对比solution/中的参考代码
6. **深入理解** - 阅读docs/中的理论文档

## 每个关卡的文件结构

```
levelXX_<name>/
├── README.md              # 关卡说明和挑战目标
├── challenge/
│   ├── vuln.c            # 漏洞程序源码
│   ├── vuln              # 编译后的二进制文件
│   ├── flag.txt.template # Flag模板（复制为flag.txt）
│   └── Makefile          # 编译脚本
├── docs/
│   ├── theory.md         # 技术原理详解
│   ├── walkthrough.md    # 逐步利用指南
│   └── hints.md          # 渐进式提示系统
└── solution/
    ├── exploit.py        # Python利用脚本
    ├── exploit.c         # C语言验证程序
    └── solver.py         # 自动化解题器
```

## 文档

- [课程介绍](docs/00_introduction.md) - 完整课程概述
- [前置知识](docs/01_prerequisites.md) - 需要掌握的基础知识
- [环境配置](docs/02_environment_setup.md) - 详细的环境配置指南
- [调试工具](docs/03_debugging_tools.md) - GDB/Pwndbg/Gef使用指南
- [堆内部原理](docs/04_heap_internals.md) - glibc malloc深入讲解
- [利用保护机制](docs/05_exploit_mitigations.md) - ASLR、PIE等保护机制

## 测试

```bash
# 编译所有关卡
cd build && make

# 运行所有测试
./tests/test_all_levels.sh

# 测试单个关卡
./tests/test_level.sh 01

# 带保护编译
cmake -DENABLE_PROTECTIONS=ON ..
make
```

## 示例：Level 1 挑战

```c
// level01_overflow/challenge/vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void winner() {
    char flag[64];
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("Error: Create flag.txt first!\n");
        return;
    }
    fread(flag, 1, sizeof(flag), f);
    printf("Flag: %s\n", flag);
}

int main() {
    char *chunk1, *chunk2;

    chunk1 = malloc(32);
    chunk2 = malloc(32);

    printf("Enter data for chunk1: ");
    read(0, chunk1, 100);  // 漏洞：堆溢出！

    if (strcmp(chunk2, "pwned!") == 0) {
        winner();
    }

    free(chunk1);
    free(chunk2);
    return 0;
}
```

**目标**：通过堆溢出控制chunk2的内容，使其等于"pwned!"

**解法提示**：
```bash
# 利用脚本
python3 -c "print('A'*33 + 'pwned!')" | ./level01_overflow/challenge/vuln
```

## 技术亮点

### Level 1-2: 基础堆漏洞
- 理解堆chunk结构（size, fd, bk等字段）
- 掌握堆缓冲区溢出
- 学习Use-After-Free概念

### Level 3-4: 核心利用技巧
- Fastbin双重释放
- Tcache poisoning（glibc 2.26+）
- 任意地址读写原语

### Level 5-6: 高级布局技术
- 堆喷射：控制内存布局
- 堆风水：精确控制chunk位置
- 多bin协调利用

### Level 7: 专家级技术
- Safe Linking绕过（glibc 2.32+）
- House of Einherjar/Force
- 现代保护机制绕过

## 常见问题

### Q: 我需要什么基础？
A: 需要掌握：
- C语言基础（指针、结构体、内存管理）
- Linux命令行操作
- 基本的调试概念
- （可选）CTF Pwn题经验

### Q: 为什么选择Docker环境？
A: Docker提供：
- 隔离的安全环境
- 统一的glibc版本
- 预装的调试工具
- 避免污染宿主系统

### Q: 遇到困难怎么办？
A: 按以下顺序：
1. 阅读关卡文档（theory.md）
2. 查看提示（hints.md）
3. 研究利用指南（walkthrough.md）
4. 参考解法代码（solution/）
5. 查阅外部资源（见下方）

## 学习资源

### 推荐阅读
- [how2heap](https://github.com/shellphish/how2heap) - 堆利用技术百科
- [glibc heap exploitation training](https://github.com/SecurityInnovation/glibc_heap_exploitation_training)
- [Azeria Labs - Heap Exploitation](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)

### 参考项目
- [HeapLAB](https://archive.ringzer0.training/archive/2020-august/heaplab-glibc-heap-exploitation.html)
- [pwnable.tw](https://pwnable.tw/) - 实战Pwn挑战

### 工具推荐
- [Pwndbg](https://github.com/pwndbg/pwndbg) - GDB增强插件
- [Pwntools](https://docs.pwntools.com/) - Python利用开发框架
- [GEF](https://github.com/hugsy/gef) - 另一个优秀的GDB插件

## 贡献指南

欢迎贡献！你可以：
- 🐛 报告bug
- 💡 提出新关卡想法
- 📖 改进文档
- 🔧 优化代码
- 🌟 推广项目

## 免责声明

### ⚠️ 教育目的声明

本项目仅用于**教育和学习目的**。所教授的技术应该：

✅ **允许使用**：
- 在你拥有的系统上练习
- 在明确授权的渗透测试中使用
- 在CTF竞赛中使用
- 在安全研究环境中使用

❌ **严禁使用**：
- 未经授权访问他人系统
- 进行恶意攻击
- 窃取数据或造成损害
- 任何非法活动

### 安全提示

- 所有挑战在隔离的Docker环境中运行
- 真实世界应用有额外的保护机制
- 仅在学习环境中应用这些技术
- 遵守所有法律法规和道德准则

## 致谢

本项目受到以下资源的启发：
- [how2heap](https://github.com/shellphish/how2heap) by Shellphish
- [glibc_heap_exploitation_training](https://github.com/SecurityInnovation/glibc_heap_exploitation_training)
- [HeapLAB](https://archive.ringzer0.training/archive/2020-august/heaplab-glibc-heap-exploitation.html)
- Azeria Labs的精彩教程

## 许可证

本项目仅供教育使用。详见 [LICENSE](LICENSE) 文件。

---

**开始学习**: [Level 0 - 环境配置](level00_setup/) →

**有问题?** 查看 [常见问题](#常见问题) 或提交 [Issue](https://github.com/yourusername/heap-mastery-course/issues)

**祝你学习愉快！Happy Hacking! 🎓**
