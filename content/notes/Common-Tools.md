---
title: "常用工具 Common Tools"
---

# 常用工具

---

`SSH`、`Netcat`、`Tmux` 和 `Vim` 等工具对于大多数信息安全专业人员来说是必不可少的，并且在日常工作中经常使用。尽管这些工具并不是专门用于渗透测试，但它们对于渗透测试过程非常关键，因此我们必须熟练掌握它们。

---

## 使用 SSH

[Secure Shell (SSH)](https://en.wikipedia.org/wiki/SSH_(Secure_Shell)) 是一种网络协议，默认在端口 `22` 上运行，并为系统管理员等用户提供了一种安全访问远程计算机的方式。SSH 可以配置为使用密码验证或无密码验证，后者使用 SSH 公钥/私钥对。SSH 可用于远程访问同一网络上的系统、通过端口转发/代理连接到其他网络中的资源，以及在远程系统之间上传/下载文件。

SSH 使用客户端-服务器模型，将运行 SSH 客户端应用程序（如 `OpenSSH`）的用户连接到 SSH 服务器。在攻击一个目标主机或进行真实世界的评估过程中，我们经常获得明文凭据或可以利用的 SSH 私钥，以便通过 SSH 直接连接到系统。SSH 连接通常比反向 shell 连接更稳定，通常可以用作“跳板主机”来枚举和攻击网络中的其他主机、传输工具、设置持久性等。如果我们获得了一组凭据，我们可以使用 SSH 通过使用用户名 `@` 远程服务器 IP 远程登录到服务器，如下所示：

```Plaintext
jw0610a@htb[/htb]$ ssh Bob@10.10.10.10

Bob@remotehost's password: *********

Bob@remotehost#
```

还可以读取被入侵系统上的本地私钥或添加我们的公钥以获得对特定用户的 SSH 访问权限，这将在后面的章节中讨论。如我们所见，SSH 是一个很好的安全连接远程计算机的工具。它还提供了一种将远程主机上的本地端口映射到我们的本地主机的方法，这在某些情况下非常方便。

---

## 使用 Netcat

[Netcat](https://linux.die.net/man/1/nc)（或称为 `ncat` 或 `nc`）是一种出色的网络实用工具，用于与 TCP/UDP 端口进行交互。在渗透测试过程中，它可以用于许多方面。它的主要用途是连接到 shell，这将在本章后面讨论。除此之外，`netcat` 还可以用于连接到任何监听端口并与运行在该端口

上的服务进行交互。例如，`SSH` 被设计用于处理通过端口 22 发送的所有数据和密钥。我们可以使用 `netcat` 连接到 TCP 端口 22：

```Plaintext
jw0610a@htb[/htb]$ netcat 10.10.10.10 22

SSH-2.0-OpenSSH_8.4p1 Debian-3
```

正如我们所见，端口 22 向我们发送了其横幅，表明正在运行 `SSH`。这种技术称为 `Banner Grabbing`，可以帮助识别特定端口上运行的服务。`Netcat` 在大多数 Linux 发行版中预装。我们还可以从此 [链接](https://nmap.org/download.html) 下载 Windows 版本的副本。`PowerCat` 是 PowerShell 中的另一种类似于 `netcat` 的替代品，它可以用来进行网络交互。`Netcat` 还可以用于在不同机器之间传输文件，这将在后面讨论。

另一个类似的网络实用工具是 [socat](https://linux.die.net/man/1/socat)，它具有一些 `netcat` 不支持的功能，比如端口转发和连接到串行设备。`Socat` 还可以用于将 shell 升级为完全交互式的 TTY。我们将在后面的章节中看到几个示例。`Socat` 是一个非常方便的工具，应该成为每个渗透测试人员工具包中的一部分。可以从此 [链接](https://github.com/andrew-d/static-binaries) 下载 `Socat` 的独立二进制文件，并在获取远程代码执行后将其传输到系统，以获得更稳定的反向 shell 连接。

---

## 使用 Tmux

终端复用器，如 `tmux` 或 `Screen`，是扩展标准 Linux 终端功能的优秀工具，它可以在一个终端中拥有多个窗口并在它们之间切换。让我们看一些使用 `tmux` 的示例，它是这两者中更常见的工具。如果在 Linux 系统上没有安装 `tmux`，可以使用以下命令进行安装：

```Plaintext
jw0610a@htb[/htb]$ sudo apt install tmux -y
```

安装完 `tmux` 后，可以输入 `tmux` 命令启动它：

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=NzU1MTExYjdkMDI5OTg4MDJmOWM5NzgwMTEzNzI5Mjdfd3Jad1BlVElFM3JTakJPM2txY3NEY1RKWjF2dWNzeDRfVG9rZW46RFFJemJGVzU3b1FNbnZ4TTMzcmNyeFNzbnNoXzE2ODY0MTM4MDE6MTY4NjQxNzQwMV9WNA)

`tmux` 命令前缀的默认键是 `[CTRL + B]`。要在 `tmux` 中打开一个新窗口，可以按下前缀键（例如 `[CTRL + B]`），然后按下 `C`：

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=ZGQ4MDg0MGI5ODQ2NzQwMmE0MDBhY2E3Njg1ZDAxOTFfN3Z2VzVoaFZCUm8zYzIxTXVaaHJWeGVWeFJKUjF0YnFfVG9rZW46TXIxMmI5MkdLb0xDbWZ4bFRjSWM4WjBmbmljXzE2ODY0MTM4MDE6MTY4NjQxNzQwMV9WNA)

我们可以在底部看到带有编号的窗口。可以通过输入前缀和窗口号（如 `0` 或 `1`）切换到每个窗口。我们还可以通过按下前缀和 `[SHIFT + %]` 将窗口垂直分割为窗格：

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=OTUxMjQzYjRlNDA0MmIzMDkyYjM4NTgyNTNkMWE1YzdfODQ0TG5ISG5IY2FRSE5UeDNIcGVUMktiUDdvakJsdGhfVG9rZW46S2FVN2I1YVRwb0M0Zmx4SVdkbmN5Umw5blpiXzE2ODY0MTM4MDE6MTY4NjQxNzQwMV9WNA)

我们还可以通过按下前缀和 `[SHIFT + "]` 将窗口水平分割为窗格：

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=Yzg1ZDQzZDg4ZjQ2YzFlOGViNjNhODIzN2JkNTQyOGRfTHljTmVSMUVwMXRsNTRyVWhPZHBWV3hkQ3dSSk85ZDlfVG9rZW46UUxDYWI2QmZ6b1JTY0x4Q2V5M2NZVDBQbmlmXzE2ODY0MTM4MDE6MTY4NjQxNzQwMV9WNA)

我们可以通过按下前缀键，然后按下 `左` 或 `右` 方向键进行水平切换，或按下 `上` 或 `下` 方向键进行垂直切换，切换窗格。上述命令涵盖了一些基本的 `tmux` 使用方法。它是一个功能强大的工具，可以用于许多方面，包括日志记录，在任何技术任务中非常重要。这个 [速查表](https://tmuxcheatsheet.com) 是一个非常方便的参考。另外，`ippsec` 的这个 [Introduction to tmux](https://www.youtube.com/watch?v=Lqehvpe_djs) 视频也值得一看。

---

## 使用 Vim

[Vim](https://linuxcommand.org/lc3_man_pages/vim1.html) 是一个出色的文本编辑器，可以用于在 Linux 系统上编写代码或编辑文本文件。使用 `Vim` 的一个巨大优势是它完全依赖于键盘，因此不需要使用鼠标，这将显著提高编写/编辑代码的生产力和效率。我们通常会在被入侵的 Linux 系统上找到 `Vim` 或 `Vi`，因此学习如何使用它可以使我们即使在远程系统上也能编辑文件。`Vim` 还具有许多其他功能，如扩展和插件，可以大大扩展其用途，并成为一个出色的代码编辑器。让我们看一下 `Vim` 的一些基础知识。要使用 `Vim` 打开文件，可以在其后添加文件名：

```Plaintext
jw0610a@htb[/htb]$ vim /etc/hosts
```

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=OTEwMDRlMDA4ZDY1M2QxNmExZGRhYmE2NzZlNzgxYTdfMFI4Y05nZnBNak9EblRSUWlaUHJ2YWdDbzUyOVZvcFZfVG9rZW46QTl2bGJQcDBlb09xMkx4UUs1WWNTVTBibmdlXzE2ODY0MTM4MDE6MTY4NjQxNzQwMV9WNA)

如果我们想创建一个新文件，输入新文件名，`Vim` 将打开一个新窗口并显示该文件。一旦我们打开了一个文件，就处于只读的 `normal mode` 中，可以浏览和阅读文件。要编辑文件，我们按下 `i` 进入 `insert mode`，在 `Vim` 底部显示 "`-- INSERT --`"：

![vim_2](https://academy.hackthebox.com/storage/modules/77/getting_started_vim_2.jpg)

然后，我们可以移动光标并编辑文件的内容。

编辑文件完成后，我们可以按下 `esc` 键退出 `insert mode`，返回到 `normal mode`。在 `normal mode` 下，可以使用以下键来执行一些有用的快捷键：

|   |   |
|---|---|
|命令|描述|
|`x`|删除字符|
|`dw`|删除单词|
|`dd`|删除整行|
|`yw`|复制单词|
|`yy`|复制整行|
|`p`|粘贴|

提示：可以在命令前面添加一个数字来多次运行任何命令。例如，'4yw' 将复制 4 个单词，依此类推。

如果要保存文件或退出 `Vim`，必须按下 `:` 进入 `command mode`。在进入 `command mode` 后，我们将在 `vim` 窗口底部看到输入的任何命令：

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=NTBhOTFlN2Q5NjQ4NzE5NTdlNzY1ZTkyZWY0OWJhZDNfM1R1dVBKQUthMEhPWlB6WWxnWFJOZ2JWVDdJY0RNb2hfVG9rZW46THN3bWI2Z1Vyb2JLQXZ4T2t6VGNyN2x1bnJiXzE2ODY0MTM4MDE6MTY4NjQxNzQwMV9WNA)

有许多可用的命令。以下是其中一些：

|   |   |
|---|---|
|命令|描述|
|`:1`|转到第 1 行|
|`:w`|写入文件，保存|
|`:q`|退出|
|`:q!`|强制退出，不保存|
|`:wq`|写入并退出|

`Vim` 是一个非常强大的工具，还有许多其他命令和功能。这个 [速查表](https://vimsheet.com) 是进一步掌握 `Vim` 强大功能的一个很好的资源。