---
title: 提权
---
# 提权

我们对远程服务器的初始访问通常是在低权限用户的上下文中，这不会给予我们对主机的完全访问权限。为了获取完全访问权限，我们需要找到一个内部/本地漏洞，该漏洞将使我们的权限提升到Linux上的`root`用户，或者Windows上的`administrator`/`SYSTEM`用户。让我们一起了解一些常见的特权提升方法。

## 提权检查清单

一旦我们获得了对主机的初始访问权限，我们希望彻底枚举该主机，以找到我们可以利用的潜在漏洞，以实现更高的特权级别。我们可以在网上找到许多清单和备忘单，其中包含了一系列我们可以运行的检查项以及运行这些检查项的命令。一个出色的资源是 [HackTricks](https://book.hacktricks.xyz)，它有一个出色的针对 [Linux](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist) 和 [Windows](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation) 的本地特权升级清单。另一个出色的仓库是 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)，它也有针对 [Linux](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) 和 [Windows](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md) 的检查清单。我们必须开始尝试各种命令和技术，并熟悉它们，以了解可能导致提升特权的多个弱点。

## 枚举脚本

上述许多命令可以通过脚本自动运行，以便遍历报告并查找任何弱点。我们可以运行许多脚本，通过运行返回任何有趣发现的常见命令来自动枚举服务器。一些常见的 Linux 枚举脚本包括 [LinEnum](https://github.com/rebootuser/LinEnum.git) 和 [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)，而对于 Windows，则包括 [Seatbelt](https://github.com/GhostPack/Seatbelt) 和 [JAWS](https://github.com/411Hall/JAWS)。

我们还可以使用用于服务器枚举的另一个有用工具，即 [Privilege Escalation Awesome Scripts SUITE (PEASS)](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)，它经过良好维护以

保持最新，并包含用于枚举 Linux 和 Windows 的脚本。

注意：这些脚本将运行许多已知用于识别漏洞的命令，并创建许多可能触发防病毒软件或安全监控软件的“噪音”，这些软件会监视此类事件。这可能会阻止脚本运行，甚至触发系统被入侵的警报。在某些情况下，我们可能希望进行手动枚举，而不是运行脚本。

让我们以运行来自 `PEASS` 的 Linux 脚本 `LinPEAS` 为例：

```Plaintext
jw0610a@htb[/htb]$ ./linpeas.sh
...SNIP...

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 3.9.0-73-generic
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...SNIP...
```

正如我们所看到的，一旦脚本运行，它就会开始收集信息并在一个优秀的报告中显示出来。让我们讨论一下我们应该从这些脚本的输出中寻找的一些漏洞。

## 内核利用

每当我们遇到运行旧操作系统的服务器时，我们应该首先寻找可能存在的内核漏洞。如果服务器没有进行最新的更新和补丁，那么它很可能容易受到存在于未打补丁版本的 Linux 和 Windows 上的特定内核利用的攻击。

例如，上述脚本显示了 Linux 版本为 `3.9.0-73-generic`。如果我们在谷歌上搜索这个版本的漏洞或使用 `searchsploit`，我们会找到一个名为 `CVE-2016-5195`，也被称为 `DirtyCow` 的漏洞。我们可以搜索并下载 [DirtyCow](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs) 的漏洞利用程序，并在服务器上运行它以获取 root 访问权限。

同样的概念也适用于 Windows，因为未打补丁/旧版本的 Windows 存在许多漏洞，这些漏洞可以被用于特权提升。我们应该牢记，内核利用可能会导致系统不稳定，在生产系统上运行它们之前应该非常谨慎。最

好在实验环境中尝试它们，并且只有在明确获得客户批准和协调的情况下才在生产系统上运行。

## 易受攻击的软件

我们还应该查看已安装的软件。例如，我们可以在 Linux 上使用 `dpkg -l` 命令，或在 Windows 上查看 `C:\Program Files`，以查看系统上安装了哪些软件。我们应该寻找任何已安装软件的公开漏洞，特别是如果使用了旧版本并存在未打补丁的漏洞。

## 用户权限

在获得对服务器的访问权限后，另一个需要注意的关键方面是我们所访问用户拥有的权限。如果我们被允许以 root（或其他用户）身份运行特定命令，那么我们可能能够提升特权到 root/system 用户或以其他用户身份登录。以下是一些利用某些用户权限的常见方法：

1. Sudo
    
2. SUID
    
3. Windows 令牌权限
    

在 Linux 中，`sudo` 命令允许用户以不同的用户身份执行命令。通常情况下，它用于允许低权限用户以 root 身份执行命令，而不给予他们对 root 用户的访问权限。这通常是因为特定命令只能以 root 身份运行（如 `tcpdump`），或允许用户访问某些仅限 root 的目录。我们可以使用 `sudo -l` 命令检查我们拥有的 `sudo` 权限：

```Plaintext
jw0610a@htb[/htb]$ sudo -l

[sudo] password for user1:
...SNIP...

User user1 may run the following commands on ExampleServer:
    (ALL : ALL) ALL
```

上面的输出显示我们可以使用 `sudo` 运行所有命令，这给了我们完全访问权限，我们可以使用 `sudo` 结合 `su` 命令切换到 root 用户：

```Plaintext
jw0610a@htb[/htb]$ sudo su -

[sudo] password for user1:
whoami
root
```

上面的命令要求输入密码才能使用 `sudo` 运行任何命令。但也有某些情况下，我们可能被允许在不需要提供密码的情况下执行特定应用程序或所有应用程序：

```Plaintext
jw0610a@htb[/htb]$ sudo -l

    (user : user) NOPASSWD: /bin/echo
```

`NOPASSWD` 条目显示可以在不需要密码的情况下执行 `/bin/echo` 命令。如果我们通过漏洞获得了对服务器的访问权限，但没有用户的密码，这将非常有用。由于它指定了 `user`，我们可以作为该用户而不是作

为 root 运行 `sudo`。为此，我们可以使用 `-u user` 指定用户：

```Plaintext
jw0610a@htb[/htb]$ sudo -u user /bin/echo Hello World!

    Hello World!
```

一旦我们找到可以使用 `sudo` 运行的特定应用程序，我们可以寻找利用它们以获取 root 用户 shell 访问权限的方法。[GTFOBins](https://gtfobins.github.io) 包含了一份命令列表以及如何通过 `sudo` 利用它们的信息。我们可以搜索我们具有 `sudo` 权限的应用程序，如果存在的话，它可能会告诉我们使用我们拥有的 `sudo` 权限来获取 root 访问权限的确切命令。

[LOLBAS](https://lolbas-project.github.io/) 也包含了一份 Windows 应用程序列表，我们可以利用它们执行特定功能，如下载文件或在特权用户上下文中执行命令。

## 计划任务

在 Linux 和 Windows 中，有一种方法可以定期运行脚本以执行特定任务。一些示例包括每小时运行一次防病毒扫描或每 30 分钟运行一次备份脚本。通常有两种方式可以利用计划任务（Windows）或 cron 作业（Linux）来提升我们的特权：

1. 添加新的计划任务/ cron 作业
    
2. 欺骗它们执行恶意软件
    

最简单的方法是检查我们是否被允许添加新的计划任务。在 Linux 中，通过 `Cron Jobs` 通常是维护计划任务的常见方式。如果我们对某个目录具有 `write` 权限，我们可以利用它来添加新的 cron 作业。这些目录包括：

1. `/etc/crontab`
    
2. `/etc/cron.d`
    
3. `/var/spool/cron/crontabs/root`
    

如果我们可以写入被 cron 作业调用的目录，我们可以编写一个包含反向 shell 命令的 bash 脚本，当执行时它应该将反向 shell 发送给我们。

## 暴露的凭据

接下来，我们可以查找我们可以读取的文件，并查看它们是否包含任何暴露的凭据。这在 `配置` 文件、`日志` 文件和用户历史文件（Linux 中的 `bash_history` 和 Windows 中的 `PSReadLine`）中非常常见。我们在开始时讨论的枚举脚本通常会在文件中搜索潜在的密码，并将其提供给我们，如下所示：

```Plaintext
...SNIP...
[+] Searching passwords in config PHP files
[+] Finding passwords inside logs (limit 70)
...SNIP...
/var/www/html/config.php: $conn = new mysqli(localhost, 'db_user', 'password123');
```

正如我们所看到的，数据库密码

`password123` 被暴露出来，这将允许我们登录到本地的 `mysql` 数据库并查找有趣的信息。我们还可以检查 `密码重用`，因为系统用户可能会将他们的密码用于数据库，这可能允许我们使用相同的密码切换到该用户，如下所示：

```Plaintext
jw0610a@htb[/htb]$ su -

Password: password123
whoami

root
```

我们还可以使用用户凭据以该用户的身份进行 `ssh` 登录到服务器。

## SSH 密钥

最后，让我们讨论一下 SSH 密钥。如果我们对特定用户的 `.ssh` 目录具有读取权限，我们可以读取其位于 `/home/user/.ssh/id_rsa` 或 `/root/.ssh/id_rsa` 的私钥，并将其用于登录到服务器。如果我们能够读取 `/root/.ssh/` 目录并且能够读取 `id_rsa` 文件，我们可以将其复制到我们的计算机，并使用 `-i` 标志使用它进行登录：

```Plaintext
jw0610a@htb[/htb]$ vim id_rsa
jw0610a@htb[/htb]$ chmod 600 id_rsa
jw0610a@htb[/htb]$ ssh user@10.10.10.10 -i id_rsa

root@remotehost#
```

请注意，我们在创建密钥后，在我们的机器上对密钥使用了 `chmod 600 id_rsa` 命令，将文件的权限更改为更严格。如果 SSH 密钥的权限过于宽松，例如可以被其他人读取，那么 SSH 服务器将阻止它们的工作。

如果我们发现可以写入用户的 `/.ssh/` 目录，我们可以将我们的公钥放在用户的 SSH 目录下的 `/home/user/.ssh/authorized_keys`。通常，这种技术用于在作为该用户的 shell 上获取 shell 后获得 ssh 访问权限。当前的 SSH 配置不接受由其他用户编写的密钥，因此仅在我们已经控制了该用户后才有效。我们首先使用 `ssh-keygen` 和 `-f` 标志创建一个新的密钥：

```Plaintext
jw0610a@htb[/htb]$ ssh-keygen -f key

Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): *******
Enter same passphrase again: *******

Your identification has been saved in key
Your public key has been saved in key.pub
The key fingerprint is:
SHA256:...SNIP... user@parrot
The key's randomart image is:
+---[RSA 3072]----+
|   ..o.++.+      |
...SNIP...
|     . ..oo+.    |
+----[SHA256]-----+
```

这将给我们两个文件：`key`（我们将与 `ssh -i` 一起使用）和 `key.pub`，我们将把它复制到远程机器上。让我们复制 `key.pub`，然后在远程机器上将其添加到 `/root/.ssh/authorized_keys` 中：

```Plaintext
user@remotehost$ echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
```

现在，远程服务器应该允许我们使用我们的私钥以该用户的身份登录：

```Plaintext
jw0610a@htb[/htb]$ ssh root@10.10.10.10 -i key

root@remotehost#
```

正如我们所看到的，我们现在可以作为用户 `root` 进行 ssh 登录。[Linux Privilege Escalation](https://academy.hackthebox.com/module/details/51) 和 [Windows Privilege Escalation](https://academy.hackthebox.com/module/details/67) 模块对如何使用这些方法以及许多其他方法进行特权提升进行了更详细的介绍。