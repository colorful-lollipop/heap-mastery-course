# 堆精通课程 - 学习路径指南

## 🎯 课程概述

本课程通过8个渐进式关卡，教授从基础到高级的堆漏洞利用技术。每个关卡都包含实践挑战和详细的理论说明。

## 📊 学习路径图

```
┌─────────────────────────────────────────────────────────────┐
│                    Heap Mastery Learning Path               │
└─────────────────────────────────────────────────────────────┘

Level 0: 环境配置
├─ 配置gcc, gdb, pwndbg, pwntools
├─ 理解堆的基本概念
└─ 难度: ⭐

     ↓
     ↓
Level 1: 堆溢出基础 ★ 必修
├─ 理解chunk结构
├─ 学习堆缓冲区溢出
├─ 第一次利用成功!
└─ 难度: ⭐

     ↓
     ↓
Level 2: Use-After-Free ★ 必修
├─ Dangling pointer概念
├─ 堆重用机制
├─ 数据破坏和权限提升
└─ 难度: ⭐⭐

     ↓
     ↓
    ┌──────────────────┐
    │  分叉点          │
    └──────────────────┘
     ↓              ↓
Level 3         Level 4
Fastbin Dup    Tcache
(⭐⭐⭐)        (⭐⭐⭐)
     ↓              ↓
     └──────────────────┐
                       ↓
                  Level 5
              Heap Spraying
                (⭐⭐⭐⭐)
                       ↓
                  Level 6
              Heap Feng Shui
               (⭐⭐⭐⭐⭐)
                       ↓
                  Level 7
           Advanced Techniques
            (⭐⭐⭐⭐⭐+)
```

## 📚 前置知识要求

### 必备知识
- C语言基础
- 指针和内存管理
- 基本的Linux命令
- 十六进制和位运算

### 推荐准备
```bash
# 完成Level 0环境检查
./build/level00_setup/check_env

# 检查glibc版本
./build/glibc_info
```

## 🔍 各关卡详细说明

### Level 0: 环境配置与基础

**学习时间**: 30分钟 - 1小时
**技能目标**:
- ✅ 配置完整的开发环境
- ✅ 运行第一个堆程序
- ✅ 使用GDB和Pwndbg

**完成标准**:
- [ ] check_env 通过所有测试
- [ ] 能独立编译并运行堆程序
- [ ] 理解堆vs栈的区别

**下一步**: 完成后进入 Level 1

---

### Level 1: 堆溢出基础 ⭐ 必修

**学习时间**: 1-2小时
**技能目标**:
- ✅ 理解堆chunk的元数据结构
- ✅ 掌握堆缓冲区溢出原理
- ✅ 编写第一个堆利用脚本

**完成标准**:
- [ ] 成功利用溢出控制chunk2
- [ ] 理解为什么需要32字节填充
- [ ] 能独立编写exploit脚本

**关键概念**:
- Chunk结构: `prev_size | size | user_data`
- 堆的连续性
- 计算chunk之间的偏移

**下一步**: 必须完成后进入 Level 2

---

### Level 2: Use-After-Free ⭐⭐ 必修

**学习时间**: 2-3小时
**技能目标**:
- ✅ 理解UAF漏洞原理
- ✅ 掌握堆重用机制
- ✅ 通过UAF实现权限提升

**完成标准**:
- [ ] 成功通过UAF修改admin权限
- [ ] 理解dangling pointer的概念
- [ ] 能用GDB观察堆重用过程

**关键概念**:
- Dangling pointer
- Fastbin/Tcache重用
- 类型混淆

**下一步**: 完成后可进入 Level 3 或 Level 4

---

### Level 3: Fastbin Double Free ⭐⭐⭐

**学习时间**: 3-4小时
**技能目标**:
- ✅ 理解Fastbin的LIFO机制
- ✅ 掌握double free攻击
- ✅ 学习操纵fd指针

**完成标准**:
- [ ] 成功实现fastbin dup攻击
- [ ] 理解为什么需要中间chunk
- [ ] 能绕过基本的双重释放检测

**适用场景**:
- glibc < 2.32 (无Safe Linking)
- 需要分配特定地址

**依赖**: Level 1, Level 2

**下一步**: 可进入 Level 4 或 Level 5

---

### Level 4: Tcache Poisoning ⭐⭐⭐

**学习时间**: 3-4小时
**技能目标**:
- ✅ 理解Tcache机制 (glibc 2.26+)
- ✅ 掌握tcache double free
- ✅ 学习绕过tcache保护

**完成标准**:
- [ ] 成功实现tcache poisoning
- [ ] 理解tcache vs fastbin的区别
- [ ] 能在glibc 2.27+上完成攻击

**适用场景**:
- glibc >= 2.26
- 需要更灵活的堆操作

**依赖**: Level 1, Level 2

**下一步**: 可进入 Level 5

---

### Level 5: Heap Spraying ⭐⭐⭐⭐

**学习时间**: 2-3小时
**技能目标**:
- ✅ 理解堆喷技术
- ✅ 提高利用可靠性
- ✅ 学习堆布局控制

**完成标准**:
- [ ] 成功实现堆喷攻击
- [ ] 理解为什么需要大量分配
- [ ] 能调整堆喷策略

**适用场景**:
- 对抗ASLR
- 提高UAF成功率
- 浏览器漏洞利用

**依赖**: Level 2 (UAF基础)

**下一步**: 进入 Level 6

---

### Level 6: Heap Feng Shui ⭐⭐⭐⭐⭐

**学习时间**: 4-6小时
**技能目标**:
- ✅ 精确控制堆布局
- ✅ 理解多bin协调
- ✅ 掌握高级堆整理

**完成标准**:
- [ ] 成功实现精确的堆布局
- [ ] 能计算chunk的确切偏移
- [ ] 理解不同大小chunk的分配策略

**难度警告**:
- 需要深入理解glibc malloc
- 可能需要多次尝试
- 建议先完成前面所有关卡

**依赖**: Level 3, Level 4, Level 5

**下一步**: 进入最终挑战 Level 7

---

### Level 7: Advanced Techniques ⭐⭐⭐⭐⭐+

**学习时间**: 6-10小时
**技能目标**:
- ✅ 绕过Safe Linking (glibc 2.32+)
- ✅ 掌握House of Einherjar
- ✅ 实现函数指针劫持

**完成标准**:
- [ ] 成功绕过现代保护机制
- [ ] 实现任意地址读写
- [ ] 完成完整的利用链

**依赖**: 所有前面关卡

**完成标志**:
🎉 恭喜！你已经掌握了堆漏洞利用的核心技术！

---

## 🎓 学习建议

### 对于初学者
1. **按顺序学习**: Level 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7
2. **不要跳关**: 每个关卡都依赖前面的知识
3. **多实践**: 每个关卡至少做2-3遍
4. **使用GDB**: 培养调试习惯

### 对于有经验的开发者
1. **快速过Level 0-2**: 重点是理解本课程的设计
2. **重点在Level 3-7**: 学习高级技术
3. **挑战自己**: 尝试不同的利用方法
4. **阅读源码**: 研究glibc malloc实现

### 对于CTF选手
1. **Level 1-2**: 快速熟悉环境
2. **Level 3-6**: 重点掌握，CTF常考
3. **Level 7**: 了解原理，实战中灵活运用
4. **时间分配**: 1天完成Level 0-4，2天完成Level 5-7

## ⚠️ 常见问题

### Q1: 我应该花多长时间？
**A**:
- 初学者: 2-3周
- 有经验: 1周
- CTF选手: 3-5天

### Q2: 卡关了怎么办？
**A**:
1. 查看 `docs/hints.md` 渐进式提示
2. 阅读 `docs/walkthrough.md` 完整步骤
3. 使用GDB调试观察内存
4. 参考how2heap项目

### Q3: glibc版本差异大吗？
**A**: 很大！使用 `./glibc_info` 检查你的版本。不同版本可能需要不同的技术。

### Q4: 需要数学基础吗？
**A**: 需要基本的十六进制计算和位运算。不需要高深的数学。

## 📖 推荐学习资源

### 配套资源
- [how2heap](https://github.com/shellphish/how2heap) - 必读！
- [GLIBC Malloc源码](https://sourceware.org/git/?p=glibc.git;a=tree;f=malloc)
- [CTF-Wiki](https://ctf-wiki.org/pwn/linux/glibc-heap/)

### 进阶阅读
- *The Heap Abstraction* - Doug Lea
- *Malloc Internals* - Wolfram Gloger
- *Understanding the Linux Kernel* - Daniel P. Bovet

## 🎯 完成标准

完成所有关卡后，你应该能够：
- [ ] 独立分析堆漏洞
- [ ] 编写堆利用脚本
- [ ] 理解glibc malloc实现
- [ ] 绕过常见的保护机制
- [ ] 调试复杂的堆问题

## 🏆 毕业证书

完成所有7个挑战关卡后，你可以宣称：
> "我已经掌握了堆漏洞利用的核心技术，并准备好进行授权的安全研究和CTF竞赛！"

---

**祝你学习愉快！Happy Hacking! 🎉**

记住：永远只在授权环境中使用这些技术！
