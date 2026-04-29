# JWT Key Confusion

## 题目信息

- 分类：Web
- 难度：Hard
- 关键字：JWT、源码审计、权限绕过

## 解题思路

登录接口会签发 JWT，服务端同时支持 `HS256` 和 `RS256`。当校验逻辑没有固定算法时，可以尝试将公钥当作 HMAC secret 使用，从而伪造管理员身份。

## 利用步骤

1. 获取公开的 RSA public key。
2. 将 JWT header 中的 `alg` 改为 `HS256`。
3. 将 payload 中的 `role` 修改为 `admin`。
4. 使用 public key 作为 HMAC secret 重新签名。
5. 访问隐藏路由读取 flag。

```bash
curl -H "Authorization: Bearer <token>" http://target/admin
cat /flag
```

## Flag

```text
LZCTF{W3lc0m3_T0_LZ_2026!!!}
```
