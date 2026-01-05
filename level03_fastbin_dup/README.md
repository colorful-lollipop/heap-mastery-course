# Level 3: Fastbin Double Free

**难度**: ⭐⭐⭐ (中级)
**学习目标**: 掌握 fastbin 操作和双重释放利用

## 🎯 目标

利用 double free 漏洞实现任意地址写（写入 0x4141414141414141 到 chunk[0]）

## 💡 思路

1. 分配 chunk A (fastbin 大小)
2. 释放 chunk A
3. 再次释放 chunk A (double free!)
4. 分配 chunk B (会得到 A)
5. 编辑 chunk B 修改 fd 指针
6. 再次分配获得目标地址

## 快速开始

```bash
cd level03_fastbin_dup/challenge
make && make flag
./vuln
```

## 技术原理

### Fastbin Double Free

Fastbin 是 LIFO 链表，double free 可以操纵 fd 指针：

```
初始: free(A)
fastbin: [A] → NULL

double free: free(A) again
fastbin: [A] → A → NULL  (循环!)

malloc:
  返回 A, fastbin: [A] → NULL
  再次 free(A)
  fastbin: [A] → NULL

  malloc A
  编辑 A->fd = target
  fastbin: [target] → NULL

  malloc → 返回 target!
```

## 参考资源

- [how2heap: fastbin_dup](https://github.com/shellphish/how2blob/tree/master/glibc_2.26/fastbin_dup)
- [Fastbin 攻击原理](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)

继续 **[Level 4: Tcache Poisoning](../level04_tcache/)**！
