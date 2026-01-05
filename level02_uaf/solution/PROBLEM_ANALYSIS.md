# Level 2 UAF - 问题分析

## 问题描述
本题存在UAF（Use-After-Free）漏洞：admin指针被free后仍然被使用，但**无法成功利用**。

## 漏洞分析

### 代码流程
```c
admin = malloc(sizeof(User));  // 100字节
user = malloc(sizeof(User));   // 100字节

// 选项1: 释放admin
free(admin);  // admin指针未清空

// 选项2: 编辑user
scanf("%31s", user->username);
scanf("%63s", user->bio);

// 选项3: 使用已释放的admin指针
printf("isAdmin: %d\n", admin->isAdmin);
```

### 内存布局
- admin地址: 0x...2a0
- user地址: 0x...310
- 相距: 112字节
- sizeof(User): 100字节

### 为什么无法利用

1. **内存不重叠**: admin和user是独立的两次malloc分配，地址不同
2. **没有重用**: 选项2只是编辑现有的user内存，不会触发新的malloc来重用admin的内存
3. **无溢出**: scanf("%63s")限制输入63字符+null=64字节，刚好填满bio[64]，无法溢出到isAdmin

## 根本原因

**本题设计存在根本性缺陷**。利用UAF需要：
1. ✓ 被释放的指针（admin）
2. ✗ 新的分配来重用被释放的内存

当前代码只有条件1，没有条件2。

## 修复方案

### 方案1: 添加临时分配
```c
case 2:
    // 添加临时分配，可能重用admin内存
    char *temp = malloc(100);
    printf("Temp: %p\n", temp);
    free(temp);

    // 然后编辑user
    scanf("%31s", user->username);
    scanf("%63s", user->bio);
    break;
```

### 方案2: 改为堆溢出题
去掉scanf的长度限制，允许bio溢出到isAdmin：
```c
scanf("%s", user->bio);  // 去掉%63限制
```

### 方案3: 使用堆风水
重新设计题目，通过多次free/malloc控制堆布局。

## 当前状态

- ❌ Exploit测试失败
- ❌ 题目无法按预期方式利用
- ⚠️  需要修改vuln.c设计

## 建议

作为教学课程，建议：
1. 修改vuln.c添加临时malloc
2. 或者明确说明这是"不完整UAF"示例，需要后续技巧
3. 调整难度评级
