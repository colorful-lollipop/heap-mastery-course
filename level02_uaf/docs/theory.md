# Level 2: Use-After-Free - 理论背景

## 什么是 Use-After-Free?

Use-After-Free (UAF) 是一种内存破坏漏洞，发生在程序使用已经释放的内存时。

## 基本概念

### 堆内存生命周期

```
1. Allocation (malloc)
   ↓
2. Use (read/write)
   ↓
3. Free (释放内存)
   ↓
4. [程序仍持有指针] ← UAF漏洞点!
```

### UAF 发生的条件

1. 程序释放了一块内存 (`free(ptr)`)
2. 程序没有将指针置空 (`ptr = NULL`)
3. 程序后续通过原指针访问该内存

## glibc 堆分配器行为

### Fastbin/Tcache 重用

当一个小块被释放后：
- 进入 tcache (glibc 2.26+) 或 fastbin
- 下次 malloc 可能返回同一块地址
- **关键**：新分配会覆盖旧内容

### 示例

```c
User *admin = malloc(sizeof(User));
free(admin);                    // 释放
                                // admin指针仍指向该地址

User *user = malloc(sizeof(User));
// 可能重用admin的内存!

strcpy(user->username, "hacker");
// admin->username 也被修改了!

if (admin->isAdmin == 0) {     // ← UAF!
    // 权限提升!
}
```

## UAF 的利用方式

### 1. 数据破坏
- 修改已释放对象的字段
- 改变程序逻辑
- 提升权限

### 2. 信息泄露
- 读取释放后的内存
- 获取地址信息
- 绕过 ASLR

### 3. 代码执行
- 覆盖函数指针
- 劫持虚表 (vtable)
- ROP/JOP 攻击

## 防御措施

### 编程最佳实践

```c
// ✓ 好的做法
free(ptr);
ptr = NULL;  // 立即置空

// ✗ 坏的做法
free(ptr);
// ptr仍是野指针!
```

### 编译器保护

- **Address Sanitizer (ASan)**: 检测UAF
- **Memory Tagging (ARM MTE)**: 硬件级保护

## 检测方法

```bash
# 使用 ASan 编译
gcc -fsanitize=address -g vuln.c -o vuln

# 运行
./vuln
# ASan 会报告 UAF 错误
```

## 相关技术

- **Double Free**: 两次释放同一块内存
- **Type Confusion**: 通过 UAF 改变对象类型
- **Heap Spraying**: 提高 UAF 利用成功率

## 参考资料

- [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)
- [How2Heap: unsafe_unlink](https://github.com/shellphish/how2heap)
- [glibc Malloc Internals](https://sourceware.org/glibc/wiki/MallocInternals)
