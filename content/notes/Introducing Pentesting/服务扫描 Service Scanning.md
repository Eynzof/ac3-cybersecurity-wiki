---
title: 服务扫描 Service Scanning
---
# 服务扫描

---

我们准备进一步探索一台机器！首先，我们需要识别操作系统和可能正在运行的任何可用服务。服务是在计算机上运行的应用程序，为其他用户或计算机提供一些有用的功能。我们将这些承载这些有用服务的专用机器称为“服务器”，而不是工作站，允许用户与和使用这些各种服务进行交互。我们感兴趣的是那些已经被错误配置或存在漏洞的服务。与执行服务的预期操作不同，我们希望看到是否可以迫使服务执行一些不受意图的操作，以支持我们的目标，比如执行我们选择的命令。

计算机被分配一个 IP 地址，这使得它们能够在网络上被唯一标识和访问。这些计算机上运行的服务可以被分配一个端口号，以便访问该服务。正如之前讨论的，端口号范围从1到65,535，其中1到1,023的端口范围被保留用于特权服务。端口0是TCP/IP网络中的保留端口，在TCP或UDP消息中不使用。如果有任何东西尝试绑定到端口0（如服务），它将绑定到1,024号端口以上的下一个可用端口，因为端口0被视为“通配符”端口。

为了远程访问一个服务，我们需要使用正确的 IP 地址和端口号进行连接，并使用服务理解的语言。手动检查所有65,535个端口是否有可用的服务将是繁琐的，因此已经创建了工具来自动化此过程并为我们扫描端口范围。最常用的扫描工具之一是 Nmap（Network Mapper）。

---

## Nmap

让我们从最基本的扫描开始。假设我们想对一个位于10.129.42.253的目标执行一个基本扫描。我们应该输入 `nmap 10.129.42.253` 并按回车键。我们看到 `Nmap` 扫描非常快速完成。这是因为如果我们没有指定任何附加选项，Nmap 默认只会扫描最常用的1,000个端口。扫描输出显示端口21、22、80、139和445是可用的。

```Plaintext
jw0610a@htb[/htb]$ nmap 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:07 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp open http
139/tcp open netbios-ssn
445/tcp open microsoft-ds
Nmap done: 1 IP address (1 host up) scanned in 2.19 seconds
```

在 `PORT` 标题下，它还告诉我们这些是 TCP 端口。默认情况下，`Nmap` 将进行 TCP 扫描，除非明确要求执行 UDP 扫描。`STATE` 标题确认了这些端口是开放的。有时，我们会看到其他列出的具有不同状态的端口，例如 `filtered`。如果防火墙只允许从特定地址访问端口，则会发生这种情况。`SERVICE` 标题告诉我们服务的名称通常映射到特定端口号。然而，默认的扫描不会告诉我们在该端口上监听的是什么。除非我们指示 `Nmap` 与服务进行交互并尝试提取识别信息，否则它可能是完全不同的服务。

随着熟悉程度的提高，我们会注意到几个端口通常与 Windows 或 Linux 相关联。例如，端口3389是远程桌面服务的默认端口，这表明目标是一台 Windows 机器的一个很好的指示。在我们当前的场景中，端口22（SSH）的可用性表明目标正在运行 Linux/Unix，但是这个服务也可以在 Windows 上配置。让我们运行一个更高级的 `Nmap` 扫描，并收集有关目标设备的更多信息。

我们可以使用 `-sC` 参数指定使用 `Nmap` 脚本来尝试获取更详细的信息。`-sV` 参数指示 `Nmap` 执行版本扫描。在这个扫描中，Nmap 将对目标系统上的服务进行指纹识别，并识别出服务协议、应用程序名称和版本。版本扫描基于一个拥有1000多个服务签名的全面数据库。最后，`-p-` 告诉 Nmap 我们要扫描所有的65,535个 TCP 端口。

```Plaintext
jw0610a@htb[/htb]$ nmap -sV -sC -p- 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:18 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).
Not shown: 65530 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Feb 25 19:25 pub
| ftp-syst: 
|   STAT: 
| FTP server status:


|      Connected to ::ffff:10.10.14.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: PHP 7.4.3 - phpinfo()
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: GS-SVCSCAN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-25T21:21:51
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 233.68 seconds
```

这返回了更多的信息。我们注意到扫描 65,535 个端口比扫描 1,000 个端口需要更长的时间。`-sC` 和 `-sV` 选项还会增加扫描的时间，因为它们不仅仅执行简单的 TCP 握手，还执行了更多的检查。我们注意到，这次有一个 VERSION 标题，报告了服务的版本以及如果可能的话识别操作系统。

到目前为止，我们知道操作系统是 Ubuntu Linux。应用程序版本也可以帮助我们揭示目标操作系统的版本。以 OpenSSH 为例。我们看到报告的版本是 `OpenSSH 8.2p1 Ubuntu 4ubuntu0.1`。通过检查其他 Ubuntu SSH 包的更改日志，我们可以看到发布版本采用的格式是 `1:7.3p1-1ubuntu0.1`。将我们的版本更新到这个格式，我们得到 `1:8.2p1-4ubuntu0.1`。在网上快速搜索这个版本，我们发现它包含在 Ubuntu Linux Focal Fossa 20.04 中。

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=YzhjMmFkMjFjYWM5NjE5NmQ1MDI3NTVkZmJjNzFhZjdfcUNReVBJSXdlZmlxTkhMZlJlOUx1Tzk4QlVzVG1rZ0lfVG9rZW46QWthbGJmVTR1b2RkSVF4ZUNKUGNlUXowbktnXzE2ODY0OTU2MTc6MTY4NjQ5OTIxN19WNA)

另一个快速搜索揭示了该操作系统的发布日期为2020年4月23日。

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=ZmU0YjUxNjFmMWUwOGMzYTM1NWI1MzNjMWMzZmUwOWJfT3ZVZ0FqOXBKdjFUNzB3UU8wNGd2ZmUwa2FlWGZQVGVfVG9rZW46R2ZJdWJ5aDVHb3pUSDZ4eWdZZWNnZG80bkdCXzE2ODY0OTU2MTc6MTY4NjQ5OTIxN19WNA)

  

我们可以进一步调查其他服务和版本。在端口21上，我们有 `vsftpd 3.0.3`。在端口80上，我们有 `Apache httpd 2.4.41`。在端口139和445上，我们有 `Samba smbd 4.6.2`。

这些信息可以帮助我们确定目标环境中可能存在的漏洞或配置错误。我们可以通过进一步研究这些服务和版本，查找已知的漏洞，并尝试利用它们来获取进一步的访问权限。