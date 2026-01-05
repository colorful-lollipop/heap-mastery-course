# Level 6: Heap Feng Shui

**难度**: ⭐⭐⭐⭐⭐ (专家级)
**学习目标**: 精确控制堆布局，高级堆整理

## 🎯 目标

通过堆风水技术实现精确的内存布局：
- chunk[9] - chunk[0] = 0x200
- chunk[5] = "FENG_SHUI"
- 至少 10 个 chunks

## 💡 思路

### 堆风水原理

通过精心设计的分配/释放序列，控制堆的物理布局：

```
目标布局：
[chunk0] (size=16)  offset 0x00
[chunk1] (size=32)  offset 0x20
[chunk2] (size=64)  offset 0x50
[chunk3] (size=16)  offset 0x90
...
[chunk9] (size=16)  offset 0x200 ← 精确位置！
```

### 利用步骤

1. **布局阶段**：分配不同大小的 chunk
2. **整理阶段**：释放特定 chunk 创建空洞
3. **重分配**：填充空洞到精确位置
4. **验证**：检查布局是否符合预期

## 技术原理

### 多 bin 协调

```
Fastbin: 16, 32, 64, 128 bytes
Tcache: per-thread cache
Small/Large bins: 更大的 chunks
```

### 对齐计算

```python
# chunk 偏移计算
chunk0 = 0x00
chunk1 = chunk0 + 0x20 (32字节 + 元数据)
chunk2 = chunk1 + 0x30 (64字节 + 元数据)
...
```

### 利用技巧

1. **堆喷射**：填充内存区域
2. **空洞创建**：释放中间的 chunk
3. **精确分配**：重用空洞到特定位置

## Python 示例

```python
from pwn import *

# 堆风水脚本
def heap_feng_shui():
    # 1. 布局
    alloc(16)  # chunk0
    alloc(32)  # chunk1
    alloc(64)  # chunk2
    # ...

    # 2. 整理
    free(1)
    free(2)

    # 3. 精确分配
    alloc(32, "FENG_SHUI")  # 重用到特定位置
```

## 参考资源

- [House of Spirit](https://heap-exploitation.dhavalkapil.com/attacks/house_of_spirit)
- [Heap Feng Shui Techniques](https://github.com/shellphish/how2heap)
- [Advanced Heap Grooming](https://github.com/DannyoVM/heap-feng-shui)

继续 **[Level 7: Advanced Techniques](../level07_advanced/)**！
