# Level 7: Advanced Techniques & Mitigation Bypass

**难度**: ⭐⭐⭐⭐⭐+ (大师级)
**glibc**: 2.32+ (Safe Linking)
**学习目标**: 绕过现代保护机制，高级利用技术

## 🎯 目标

通过高级堆利用技术劫持函数指针，调用 `winner()`：
- 绕过 Safe Linking (glibc 2.32+)
- 使用 House of Einherjar 或其他高级技术
- 劫持 `target->func_ptr` 为 `winner` 地址

## 💡 思路

### Safe Linking (glibc 2.32+)

保护 fastbin/tcache 的 fd 指针：

```
fd = L >> 12   (右移 12 位，加密)

解密时：
L = (fd << 12) | heap_base
```

### 绕过方法

1. **信息泄露**：泄露堆基址
2. **House of Einherjar**：利用 prev_size
3. **Unsafe Unlink**：经典技术
4. **House of Force**：控制 top chunk

## 技术原理

### House of Einherjar

利用 chunk 合并时的溢出：

```
1. 分配 chunk A
2. 溢出 A，修改 chunk B 的 prev_size
3. 伪造 B 为 free
4. free B → 合并到 A
5. 控制 malloc 返回任意地址
```

### House of Force

控制 top chunk 的 size：

```
1. 溢出修改 top->size 为超大值
2. malloc(target - top - 0x10)
3. 下次 malloc 返回 target
```

## 利用步骤

1. **信息收集**：泄露堆地址、libc 地址
2. **布局准备**：创建合适的堆布局
3. **漏洞触发**：溢出/UAF/double free
4. **保护绕过**：计算加密指针
5. **函数劫持**：覆写函数指针
6. **代码执行**：调用 winner()

## Python 示例

```python
from pwn import *

# Safe Linking 解密
def decrypt_safe_link(fd, heap_base):
    return ((fd << 12) & 0xFFFFFFFFFFFFFFFF) | heap_base

# 1. 泄露堆地址
heap_leak = leak_heap_base()

# 2. 利用 double free + safe linking bypass
# ... 具体利用代码 ...

# 3. 劫持 func_ptr
payload = p64(winner_addr)
write(target_address, payload)

# 4. 触发
call_function()
```

## 参考资源

- [Safe Linking 论文](https://sourceware.org/glibc/wiki/MallocInternals#Safe_Linking)
- [House of Einherjar](https://heap-exploitation.dhavalkapil.com/attacks/house_of_einherjar)
- [How2Heap: Advanced Techniques](https://github.com/shellphish/how2heap)

## 🎓 毕业要求

完成本关卡后，你已经：
- ✅ 掌握了所有核心堆利用技术
- ✅ 理解现代保护机制
- ✅ 能够编写复杂的堆利用脚本
- ✅ 准备好进行真实世界的漏洞利用研究！

## 🎉 恭喜！

你已经完成了堆精通课程的所有关卡！

继续学习：
- [Kernel Heap Exploitation](https://grsecurity.net/exploiting_heap_overflows_in_the_linux_kernel)
- [Browser Heap Exploitation](https://github.com/saelo/jscpwn)
- [Real-world CVE Analysis](https://cve.mitre.org/)

---

**Remember: With great power comes great responsibility!** 🕷️

永远只在授权环境中使用这些技术！
