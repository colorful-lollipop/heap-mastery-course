# 快速开始指南

5 分钟内开始学习堆漏洞利用！

## 方法 1: Docker（推荐）

```bash
# 1. 克隆仓库
git clone <repository>
cd heap-mastery-course

# 2. 启动容器
docker-compose up -d

# 3. 进入容器
docker-compose exec course bash

# 4. 构建并测试
mkdir build && cd build
cmake ..
make
./level00_setup/check_env
```

## 方法 2: 本地安装

```bash
# 1. 安装依赖
sudo apt-get install -y build-essential gcc gdb python3 python3-pip

# 2. 安装 Pwntools
pip3 install pwntools

# 3. 安装 Pwndbg
cd ~
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# 4. 构建项目
cd heap-mastery-course
mkdir build && cd build
cmake ..
make
```

## 验证安装

```bash
# 运行环境检查
./level00_setup/check_env

# 应该看到所有测试通过
```

## 开始第一个挑战

```bash
cd level01_overflow/challenge
make flag
./vuln

# 尝试漏洞利用
python3 -c "print('A'*32 + 'pwned!')" | ./vuln
```

## 目录结构

```
heap-mastery-course/
├── README.md              # 主文档
├── QUICKSTART.md          # 本文件
├── level00_setup/         # 从这里开始！
├── level01_overflow/      # 堆溢出基础
├── level02_uaf/          # Use-After-Free
├── level03_fastbin_dup/  # Fastbin Double Free
├── level04_tcache/       # Tcache Poisoning
├── level05_heap_spray/   # 堆喷
├── level06_feng_shui/    # 堆风水
├── level07_advanced/     # 高级技术
├── docs/                 # 详细文档
├── common/               # 共享工具
└── tests/                # 测试脚本
```

## 学习路径

```
Level 0 → Level 1 → Level 2 → ... → Level 7
 (配置)  (溢出)   (UAF)         (大师)
```

## 获取帮助

- 卡关？查看 `hints.md`
- 需要理论？查看 `docs/theory.md`
- 想看解法？查看 `solution/`

## 下一步

🚀 **开始 [Level 0: 环境配置](level00_setup/)**

---

**祝学习愉快！Happy Hacking!** 🎓
