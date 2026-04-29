# SSTI Sandbox Escape

## 题目信息

- 分类：Web
- 难度：Medium
- 关键字：SSTI、Python、沙箱逃逸

## 漏洞入口

页面会把用户输入直接拼接到模板中渲染，基础探测可以使用：

```text
{{ 7 * 7 }}
```

如果返回 `49`，说明存在模板注入。

## 利用思路

通过对象链找到可执行命令的类或函数，再绕过关键字过滤读取文件。

```bash
cat /flag
```

## Flag

```text
LZCTF{W3lc0m3_T0_LZ_2026!!!}
```
