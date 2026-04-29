# Memory Forensics Trail

## 题目信息

- 分类：Misc
- 难度：Medium
- 关键字：内存取证、流量分析、Volatility

## 取证路线

先识别镜像系统版本，再枚举进程、网络连接和命令历史。可疑进程通常会留下路径、参数或连接目标。

```bash
volatility -f mem.raw windows.pslist
volatility -f mem.raw windows.netscan
volatility -f mem.raw windows.cmdline
```

## 复盘

Misc 题的核心是建立证据链，不要只盯单个文件。网络连接、剪贴板、浏览器历史经常能互相印证。
