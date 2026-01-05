# Visual Heap Layout Diagrams

本文档包含堆利用的关键概念可视化图表，帮助理解各种攻击技术。

## 目录
1. [Chunk 结构](#chunk-结构)
2. [Fastbin 链表](#fastbin-链表)
3. [Tcache 结构](#tcache-结构)
4. [Heap Overflow](#heap-overflow)
5. [Double Free](#double-free)
6. [Heap Spraying](#heap-spraying)
7. [Heap Feng Shui](#heap-feng-shui)

---

## Chunk 结构

### Allocated Chunk (已分配)

```
┌─────────────────────────────────────────┐
│  prev_size (8 bytes)                    │  ← 仅在前一个 chunk 空闲时使用
├─────────────────────────────────────────┤
│  size (8 bytes)                         │  ← 包含用户大小 + 标志位
│  ├─ 用户数据大小 (例如: 0x20)          │
│  ├─ PREV_INUSE (1 bit)                  │  ← 前一个 chunk 是否在使用
│  ├─ IS_MMAPPED (1 bit)                  │
│  └─ NON_MAIN_ARENA (1 bit)              │
├─────────────────────────────────────────┤
│                                         │
│  User Data (N bytes)                    │  ← 用户使用的数据
│  "Hello World"                          │
│                                         │
└─────────────────────────────────────────┘

实际大小 = (用户大小 + 0x10 + 对齐) 向上对齐到 0x10

示例：malloc(32)
  用户请求: 32 字节
  头大小:   16 字节 (prev_size + size)
  总大小:   48 字节
  对齐后:   0x40 (64 字节)
  size 字段: 0x41 (0x40 | PREV_INUSE)
```

### Free Chunk (空闲)

```
┌─────────────────────────────────────────┐
│  prev_size (8 bytes)                    │
├─────────────────────────────────────────┤
│  size (8 bytes)                         │  ← PREV_INUSE = 0
├─────────────────────────────────────────┤
│  fd (forward pointer, 8 bytes)          │  ← 指向下一个空闲 chunk
├─────────────────────────────────────────┤
│  bk (backward pointer, 8 bytes)         │  ← 指向前一个空闲 chunk
├─────────────────────────────────────────┤
│  (unused)                               │  ← 未使用
└─────────────────────────────────────────┘

注：fastbin/tcache 只使用 fd，不使用 bk
```

---

## Fastbin 链表

### Fastbin 结构

```
malloc_state (main arena):
┌─────────────────────────────────────┐
│  fastbins[64]                       │
│  ├─ fastbins[0] (size 0x10)         │ → NULL
│  ├─ fastbins[1] (size 0x20)         │ → Chunk A → Chunk B → NULL
│  ├─ fastbins[2] (size 0x30)         │ → NULL
│  ├─ ...                              │
│  └─ fastbins[7] (size 0x80)         │ → Chunk C → NULL
└─────────────────────────────────────┘

Fastbin[1] (size=0x20) 链表：
┌────────┐    ┌────────┐    ┌────────┐
│Chunk A │    │Chunk B │    │Chunk C │
│0x21    │    │0x21    │    │0x21    │
│fd ─────┼───→│fd ─────┼───→│fd ─────┼───→ NULL
├────────┤    ├────────┤    ├────────┤
│数据    │    │数据    │    │数据    │
└────────┘    └────────┘    └────────┘

LIFO (后进先出):
  分配: 取链表头 (Chunk A)
  释放: 插入链表头
```

### Fastbin Double Free

```
正常状态：
fastbins[1] → A → B → C → NULL

执行:
  free(A)  // 已经在链表中
  // 检测: A == fastbins[1] ? 检测失败!

绕过方法:
  1. free(X)  // X 不同
  2. free(A)  // A 不在链表头

状态:
fastbins[1] → A → X → ... → A → NULL
              └─────────────┘
                  循环!
```

---

## Tcache 结构

### Tcache Per-thread 结构

```
Thread Local Storage:
┌─────────────────────────────────────────┐
│  tcache_perthread_struct                │
├─────────────────────────────────────────┤
│  counts[64]                             │  ← 每个 bin 的计数
│  [7, 5, 0, 3, 0, 0, ...]              │
├─────────────────────────────────────────┤
│  entries[64]                            │  ← 每个 bin 的链表头
│  [p1, p2, NULL, p4, NULL, ...]         │
└─────────────────────────────────────────┘

Tcache Bin[1] (size=0x20, count=3):
entries[1] → Chunk A → Chunk B → Chunk C → NULL

关键特性：
- 每个 bin 最多 7 个 chunk
- 填满后才进入 fastbin
- 无需加锁 (per-thread)
- Double free 检测很弱
```

### Tcache vs Fastbin 流程

```
free(chunk) 的流程：

1. 检查 tcache
   ├─ counts[tcache_idx] < 7?
   │  ├─ YES → 插入 tcache，结束
   │  └─ NO  → 继续检查 fastbin
   │
2. 检查 fastbin
   ├─ size <= FASTBIN_MAX_SIZE?
   │  ├─ YES → 插入 fastbin
   │  └─ NO  → 继续
   │
3. 检查 small/large/unsorted bin
   └─ 合并/插入对应 bin

示例：连续释放 10 个 32-byte chunks
- 前 7 个 → tcache (已满)
- 后 3 个 → fastbin
```

---

## Heap Overflow

### 基本堆溢出

```
初始状态：
┌──────────────┐
│  Chunk 1     │
│  [32 bytes]  │  ← 用户可控
└──────────────┘
┌──────────────┐
│  Chunk 2     │
│  [32 bytes]  │  ← 目标
└──────────────┘

溢出攻击：
输入 = "A" * 40 + "pwned!"

结果：
┌──────────────┐
│  Chunk 1     │
│  AAAAAA...AA │  ← 40 个 'A' 溢出
│  pwned!      │  ← 覆盖到 Chunk 2
└──────────────┘
┌──────────────┐
│  Chunk 2     │
│  pwned!      │  ← 被修改！
└──────────────┘
```

### Chunk 元数据破坏

```
Chunk 布局：
┌──────────┬───────┬──────────┐
│prev_size│ size  │data      │
├──────────┼───────┼──────────┤
│   ???    │0x21   │AAA...AAA │  ← Chunk A
├──────────┼───────┼──────────┤
│   ???    │0x21   │BBB...BBB │  ← Chunk B
├──────────┼───────┼──────────┤
│   ???    │0x21   │CCC...CCC │  ← Chunk C
└──────────┴───────┴──────────┘

溢出 Chunk A 覆盖 Chunk B 的 size：
data = "A" * 32 + "\x00" * 8 + "\x91"  # 伪造 size = 0x91

结果：
┌──────────┬───────┬──────────┐
│   ???    │0x21   │AAA...AAA │  ← Chunk A
├──────────┼───────┼──────────┤
│   ???    │0x91   │BBB...BBB │  ← size 被修改！
├──────────┴───────┴──────────┤
│   被包含进 Chunk B            │  ← Chunk C 的一部分
└──────────────────────────────┘

影响：释放 Chunk B 时会合并 Chunk C！
```

---

## Double Free

### Fastbin Double Free 攻击

```
步骤 1: 分配 3 个 chunk
┌─────────┐  ┌─────────┐  ┌─────────┐
│Chunk A  │  │Chunk B  │  │Chunk C  │
│@ 0x1000 │  │@ 0x1040 │  │@ 0x1080 │
└─────────┘  └─────────┘  └─────────┘

步骤 2: 释放 A
fastbin → A → NULL

步骤 3: 释放 C
fastbin → C → A → NULL

步骤 4: Double Free A
fastbin → A → C → A → NULL
              └─────────┘
                 循环!

步骤 5: 分配 A (从 fastbin 移除)
fastbin → C → A → NULL
         └────────┘
            指向 A

步骤 6: 编辑 A 的 fd 指针
修改 A 的 fd 为目标地址 TARGET
fastbin → C → A → TARGET → NULL

步骤 7: 分配 C (从 fastbin 移除)
fastbin → A → TARGET → NULL

步骤 8: 分配 A (从 fastbin 移除)
fastbin → TARGET → NULL

步骤 9: 下一次分配返回 TARGET!
p = malloc(size)  // 返回 TARGET！
```

---

## Heap Spraying

### 堆喷概念

```
堆喷前：
Heap (稀疏，少量 chunk)
┌──────────┐
│ chunk 1  │
└──────────┘
        ... 大量空闲空间 ...
┌──────────┐
│ chunk 2  │
└──────────┘

堆喷后（分配 100 个相同 chunk）：
Heap (密集，充满模式)
┌──────────┐
│ chunk 1  │ ← "PATTERN"
├──────────┤
│ chunk 2  │ ← "PATTERN"
├──────────┤
│ chunk 3  │ ← "PATTERN"
├──────────┤
│   ...    │ ← "PATTERN"
├──────────┤
│ chunk 100│ ← "PATTERN"
└──────────┘

结果：
- 无论分配哪个位置，都可能是我们的 chunk
- UAF/堆溢出的成功率大大提高
```

### 对抗 ASLR

```
问题：ASLR 随机化地址
解决：堆喷覆盖可能的地址范围

堆喷 10000 个对象：
┌────────────────────────────────────┐
│ Objs 1-1000   @ region 1 (可能)    │
├────────────────────────────────────┤
│ Objs 1001-2000 @ region 2 (可能)    │
├────────────────────────────────────┤
│ ...                              │
├────────────────────────────────────┤
│ Objs 9001-10000 @ region 10 (可能)  │
└────────────────────────────────────┘

即使不知道确切地址，也有高概率命中！
```

---

## Heap Feng Shui

### 精确布局控制

```
目标：创建特定大小的空洞

步骤 1: 分配多个 chunk
┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐
│  A   ││  B   ││  C   ││  D   ││  E   │
│0x20  ││0x20  ││0x20  ││0x80  ││0x20  │
└──────┘└──────┘└──────┘└──────┘└──────┘

步骤 2: 释放 B, C, D
┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐
│  A   ││  *   ││  *   ││  *   ││  E   │
│0x20  ││FREE  ││FREE  ││FREE  ││0x20  │
└──────┘┴──────┘┴──────┘┴──────┘┴──────┘
         └────────┘
        0x20+0x20+0x80 = 0xC0 空洞

步骤 3: 分配 0xC0 大小的 chunk
新 chunk 会重用 B+C+D 的空间！

结果：精确控制了新 chunk 的位置
```

### Fastbin Consolidation

```
目标：创造特定大小的 chunk

步骤 1: 填满 fastbin
fastbin[0x20] → c1 → c2 → c3 → c4 → c5 → c6 → c7

步骤 2: 触发合并
- 分配一个大 chunk (> FASTBIN_MAX)
- fastbin 中的 chunk 被合并到 unsorted bin

结果：
unsorted bin → [合并后的大 chunk]
            size = 0x20 * 7 = 0xE0

步骤 3: 从 unsorted bin 分割
- 可以得到精确大小的大 chunk
- 用于后续的堆布局
```

### Offset 计算

```
目标：chunk[N] - chunk[0] = 0x200

方法 1: 均匀大小
每个 chunk = 0x200 / N

例如 N=8:
每个 chunk = 0x200 / 8 = 0x40
实际大小 = 0x40 → 用户请求 malloc(32)

验证：
chunk[0] @ 0x1000
chunk[1] @ 0x1040
chunk[2] @ 0x1080
...
chunk[8] @ 0x1200
diff = 0x1200 - 0x1000 = 0x200 ✓

方法 2: 混合大小
使用不同大小的组合达到目标偏移
```

---

## Safe Linking (glibc 2.32+)

### Safe Linking 加密

```
传统 fastbin:
fd = 指向下一个 chunk 的地址 (明文)

Safe Linking:
fd = (L >> 12) ^ P

其中：
  L = 目标 chunk 地址
  P = 当前 chunk 地址 (堆地址)

加密示例：
L = 0x55555555a000
P = 0x555555559000

fd = (0x55555555a000 >> 12) ^ 0x555555559000
   = 0x555555 ^ 0x555555559000
   = 0x55555555a555

解密：
P = (fd ^ (L >> 12))
  = (0x55555555a555 ^ 0x555555)
  = 0x555555559000 ✓
```

### 绕过方法 1: 部分覆盖

```
原理：Safe Linking 只保护高 12 位

策略：只修改低字节，保持高字节不变

示例：
原地址: 0x55555555a000
目标:   0x55555555b000

只修改低 12 位 (0xa000 → 0xb000)

payload = p16(0xb000)  # 只覆盖 2 字节

适用场景：
- 目标地址与原地址在同一 0x1000 区域
- 通常适用于同一个堆的不同 chunk
```

### 绕过方法 2: 完整计算

```
步骤 1: 泄露堆地址
- 通过 UAF
- 通过 unsorted bin
- 通过其他原语

步骤 2: 计算正确的 fd
target = 0x55555555b000
heap_base = 0x555555550000

fd = (target >> 12) ^ heap_base
   = (0x55555555b000 >> 12) ^ 0x555555550000
   = 0x555555 ^ 0x555555550000
   = 0x55555555a555

步骤 3: 修改 fd
edit(chunk, p64(fd))

适用场景：
- 目标地址在不同区域
- 已知堆地址
- 需要精确控制
```

---

## 总结

这些图表展示了堆利用的核心技术：

1. **Chunk 结构** - 理解内存布局
2. **Fastbin/Tcache** - 快速分配机制
3. **Heap Overflow** - 基础攻击
4. **Double Free** - 链表操纵
5. **Heap Spraying** - 布局控制
6. **Heap Feng Shui** - 精确布局
7. **Safe Linking** - 现代保护

掌握这些图解，你就能理解堆利用的本质！
