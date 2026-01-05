# Level 4: Tcache Poisoning

**难度**: ⭐⭐⭐ (中级)
**glibc 版本**: 2.26+
**学习目标**: 掌握 tcache 操纵和 poisoning

## 🎯 目标

利用 tcache double free 实现任意地址写（0xdeadbeefcafebabefull）

## 💡 思路

### Tcache (glibc 2.26+)

- 每线程缓存，存储 small chunks
- 每个 bin 最多 7 个 chunks
- **Double free 检测较弱**！

### 利用步骤

1. 分配 7 个 chunks 填满 tcache
2. Double free 一个 chunk
3. 再次分配获得 chunk，修改 fd
4. 分配到目标地址

## 技术原理

```
Tcache 结构 (per-thread):
  tcache_entry[64]  // 64 个 bin，每个大小不同
  counts[64]        // 每个 bin 的计数

Double free 检查:
  只检查 tcache 中的第一个 chunk!

绕过方法:
  1. free(A)
  2. free(B)
  3. free(A)  ← 绕过检测！
```

## 参考资源

- [how2heap: tcache_poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.34/tcache_poisoning.c)
- [Tcache 详解](https://github.com/shellphish/how2heap/wiki)

继续 **[Level 5: Heap Spraying](../level05_heap_spray/)**！
