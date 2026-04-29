# VM Bytecode Crackme

## 题目信息

- 分类：Reverse
- 难度：Hard
- 关键字：虚拟机、字节码、约束求解

## 分析过程

程序实现了一个简易 VM，输入会被转换成寄存器状态，然后逐条执行自定义 bytecode。核心工作是还原 opcode 含义。

## 自动化

将 opcode 翻译成 Python 解释器后，可以把最终比较逻辑转成约束交给 Z3 求解。

```python
from z3 import *

flag = [BitVec(f'f{i}', 8) for i in range(32)]
solver = Solver()
```

## 收获

先恢复指令语义，再做自动化，比直接硬怼汇编更稳定。
