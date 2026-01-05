# 课程介绍

欢迎来到堆精通课程！

## 课程概述

这是一门全面的堆漏洞利用教学课程，通过7个难度递增的关卡，带你从零基础到精通堆漏洞利用技术。

## 你将学到

### 核心技术
- ✅ 堆溢出 (Heap Overflow)
- ✅ Use-After-Free (UAF)
- ✅ Fastbin Double Free
- ✅ Tcache Poisoning
- ✅ 堆喷 (Heap Spraying)
- ✅ 堆风水 (Heap Feng Shui)
- ✅ Safe Linking 绕过

### 实践技能
- 🔧 GDB/Pwndbg 调试技巧
- 🔧 Pwntools 利用开发
- 🔧 堆布局分析
- 🔧 漏洞利用脚本编写

## 课程结构

| 关卡 | 主题 | 难度 | 时间 |
|------|------|------|------|
| [0](../level00_setup/) | 环境配置 | ⭐ | 1h |
| [1](../level01_overflow/) | 堆溢出 | ⭐ | 2h |
| [2](../level02_uaf/) | Use-After-Free | ⭐⭐ | 3h |
| [3](../level03_fastbin_dup/) | Fastbin Dup | ⭐⭐⭐ | 4h |
| [4](../level04_tcache/) | Tcache Poisoning | ⭐⭐⭐ | 4h |
| [5](../level05_heap_spray/) | 堆喷 | ⭐⭐⭐⭐ | 6h |
| [6](../level06_feng_shui/) | 堆风水 | ⭐⭐⭐⭐⭐ | 8h |
| [7](../level07_advanced/) | 高级技术 | ⭐⭐⭐⭐⭐+ | 12h |

## 学习路径

```
开始
  ↓
Level 0: 配置环境 → 验证工具
  ↓
Level 1: 堆溢出 → 理解 chunk 结构
  ↓
Level 2: UAF → 学习堆重用
  ↓
Level 3-4: 核心技巧 → Fastbin/Tcache
  ↓
Level 5-6: 高级布局 → 堆喷/堆风水
  ↓
Level 7: 大师级 → 绕过保护
  ↓
毕业！🎓
```

## 如何使用本课程

### 方法 1: 系统学习

按照关卡顺序，从 Level 0 到 Level 7 依次完成：
1. 阅读 README.md 了解关卡目标
2. 尝试自己解决挑战
3. 遇到困难查看 hints.md
4. 阅读理论文档
5. 研究利用脚本
6. 完成后进入下一关

### 方法 2: 查阅参考

将本课程作为参考手册：
- 需要时查找特定技术
- 研究利用代码示例
- 复习理论知识

## 前置知识

### 必需
- C 语言基础（指针、结构体、内存管理）
- Linux 命令行操作
- 基本的调试概念

### 推荐但非必需
- CTF Pwn 题经验
- 汇编语言基础
- 计算机组成原理

## 工具和环境

### 必需工具
- GCC 9.0+
- GDB + Pwndbg
- Python 3 + Pwntools
- glibc 2.27-2.35

### 推荐工具
- GEF (GDB Enhanced Features)
- checksec
- ROPgadget

### 快速开始

使用 Docker（推荐）：
```bash
docker-compose up -d
docker-compose exec course bash
```

## 学习建议

### 有效学习策略

1. **理解原理**：不要只记步骤，要理解背后的原理
2. **动手实践**：每个关卡都要自己动手尝试
3. **调试分析**：使用 GDB 观察实际内存布局
4. **笔记记录**：记录关键概念和技巧
5. **总结反思**：完成后总结学到的东西

### 常见误区

❌ **错误做法**：
- 直接看答案不理解原理
- 跳过关卡顺序学习
- 只在一种 glibc 版本测试
- 忽视保护机制的影响

✅ **正确做法**：
- 先思考再查资料
- 按顺序学习
- 测试多个 glibc 版本
- 理解保护机制

## 实践项目

完成课程后，你可以：

1. **CTF 比赛**：参加真实 CTF 挑战
2. **CVE 分析**：研究真实漏洞
3. **工具开发**：开发自动化利用工具
4. **研究贡献**：分享新的利用技术

## 免责声明

⚠️ **重要声明**：

本课程仅用于教育目的。所学技术应该：

✅ **允许使用**：
- 在你拥有的系统上练习
- 在授权的渗透测试中使用
- 在 CTF 竞赛中使用
- 在安全研究环境中使用

❌ **严禁使用**：
- 未经授权访问他人系统
- 进行恶意攻击
- 窃取数据或造成损害
- 任何非法活动

## 资源和社区

### 推荐资源

- [how2heap](https://github.com/shellphish/how2heap) - 堆利用技术百科
- [Pwntools 文档](https://docs.pwntools.com/)
- [CTF Wiki](https://ctf-wiki.org/pwn/linux/)

### 社区

- CTF 时间线 (ctftime.org)
- Pwnable.kr/tw
- Exploit Education

## 开始学习

准备好开始了吗？

从 [Level 0: 环境配置](../level00_setup/) 开始你的堆利用之旅！

---

**祝学习愉快！Happy Hacking!** 🚀
