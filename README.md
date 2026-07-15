### OpenBSD Pledge/Unveil Launcher

[![Build and Release](https://github.com/sourcetf/openbsd-exec/actions/workflows/build.yml/badge.svg)](https://github.com/sourcetf/openbsd-exec/actions/workflows/build.yml)

一个单文件、自包含的 OpenBSD 权限沙箱启动器。通过 `pledge(2)` 和 `unveil(2)` 在程序启动前完成最小权限锁定，让任何普通程序都能以**最小权限原则**运行。

---

## 特性

- **单文件 C 代码** — 零依赖，仅依赖 OpenBSD 基础系统
- **三种使用模式** — 命令行直启、交互式 TUI、生成独立启动器
- **自限制设计** — 先 `unveil` 再 `pledge`，最后二次 `pledge` 收紧权限，自身也无法逃逸
- **安全的 `--make-starter`** — 编译时自动生成独立 C 启动器二进制，脱离本工具运行
- **防御性输入处理** — 所有外部输入均有长度限制、字符白名单、转义处理

---

## 构建

```sh
cc -O2 -o exec exec.c -Wall -Wextra

# 或使用 Makefile
make
```

> 本工具仅能在 OpenBSD 上编译运行，依赖 `pledge(2)` 和 `unveil(2)` 系统调用。

---

快速开始

1. 命令行直启

```sh
# 静态 Web 服务器（只读 + 网络）
./exec stdio,rpath,inet /var/www/htdocs:r -- ./darkhttpd /var/www/htdocs

# 数据库服务（读写 + 网络）
./exec stdio,rpath,wpath,cpath,inet /var/db:rwc -- ./postgres

# Shell 脚本（最小权限）
./exec stdio,rpath,exec /bin:rx,/usr/bin:rx -- /bin/sh script.sh

# 仅 pledge，不 unveil（传空字符串）
./exec stdio,rpath,inet "" -- ./myapp
```

2. 交互式 TUI（`--menuconfig`）

```sh
./exec --menuconfig
```

- `↑/↓` 移动，`Space` 切换 pledge
- `a` 添加 unveil 路径，`d` 删除
- `←/→` 切换标签页
- `Enter` 确认执行，`q` 退出

3. 生成独立启动器（`--make-starter`）

将配置固化为一个不依赖本工具的独立二进制：

```sh
./exec --make-starter webd stdio,rpath,inet /var/www/htdocs:r -- ./darkhttpd /var/www/htdocs
# 生成 ./webd
./webd           # 直接运行
./webd --help    # 查看创建参数
```

生成的启动器：
- 硬编码 pledge/unveil/命令参数
- 编译时启用栈保护、PIE、RELRO、NOW
- 使用 `mkstemp` 安全创建临时源文件

---

可用 Pledges（OpenBSD 7.5）

Pledge	说明	
`stdio`	基本 I/O、内存、定时器、管道（绝大多数程序需要）	
`rpath`	读取路径、stat、只读打开	
`wpath`	写入路径	
`cpath`	创建/删除文件和目录	
`inet`	TCP/IPv4、IPv6 套接字	
`unix`	UNIX 域套接字	
`dns`	DNS 解析（读取 `/etc/resolv.conf`）	
`proc`	进程创建（fork、kill）	
`exec`	执行程序（必须包含）	
`tty`	终端设备操作	
`getpw`	读取用户/组数据库	
`error`	违规时返回 `ENOSYS` 而非 `SIGABRT`（调试用）	
...	完整列表见 `./exec --help`	

---

Unveil 路径语法

```
/path/to/dir:perms
```

- `r` — 读取
- `w` — 写入
- `x` — 执行
- `c` — 创建/删除

路径含特殊字符时用双引号包裹，内部用 `\` 转义：

```sh
./exec stdio,rpath,wpath "/tmp/my:dir":rwc,/var/log:rwc -- ./myapp
./exec stdio,rpath "/tmp/my\"dir":rwc -- ./myapp
```

---

安全设计

自限制流程

```
1. unveil(路径, 权限)  — 暴露必要的文件系统视图
2. unveil(NULL, NULL)   — 锁定 unveil，后续不可更改
3. pledge(用户承诺, 用户承诺)  — 第一次限制
4. pledge(stdio exec, 用户承诺) — 第二次收紧，自身也无法扩展权限
5. execvp(目标程序)     — 执行被保护程序
```

输入安全

- 所有字符串输入均有 `MAX_*` 硬上限
- 使用 `strlcpy` / `strlcat` / `snprintf`，无缓冲区溢出
- `--make-starter` 使用 `c_escape()` 转义 `\` 和 `"`，防止生成的 C 源代码注入
- 启动器名称白名单：`[-_.a-zA-Z0-9]`，防止路径遍历
- 编译临时文件使用 `mkstemp()`，防止 TOCTOU

---

CI/CD

本项目使用 GitHub Actions 在 真实 OpenBSD 虚拟机 中自动构建。

- 每次 push 到 `main` 自动编译
- 构建产物自动上传至 [Releases](https://github.com/sourcetf/openbsd-exec/releases)
- 支持手动触发（`workflow_dispatch`）

---

调试技巧

```sh
# 使用 error pledge 找出缺失的权限（不会崩溃，返回 ENOSYS）
./exec stdio,rpath,error /var/www:r -- ./myserver
# 查看 /var/log/messages 中的违规记录

# 查看生成的 starter 源码（在编译失败时临时文件会被保留用于排查）
```

---

限制

- 仅支持 OpenBSD。`pledge(2)` 和 `unveil(2)` 是 OpenBSD 特有系统调用。
- 目标程序所需的权限必须由用户显式声明，工具不会自动推断。
