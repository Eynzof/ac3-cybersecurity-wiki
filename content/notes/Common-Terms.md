---
title: "常用术语 Common Terms"
---

# 常见术语

---

渗透测试/黑客攻击是一个庞大的领域。在我们的职业生涯中，我们将遇到无数的技术。以下是一些最常见的术语和技术，我们将反复遇到并且必须牢牢掌握。这并非是一个详尽无遗的清单，但足以开始基础模块和简单的[[notes/Hack The Box|HTB]]题目。

---

## 什么是 Shell？

`Shell` 是一个我们在旅程中一再听到的常见术语。它有几个含义。

在 Linux 系统上，Shell 是一个接受用户通过键盘输入的程序，将这些命令传递给操作系统执行特定功能。在计算机的早期阶段，Shell 是与系统进行交互的唯一界面。此后，随着图形用户界面（GUI）出现以补充命令行界面（Shell），诸如 Linux 终端、Windows 命令行（cmd.exe）和 Windows PowerShell 等许多其他操作系统类型和版本也出现了。

大多数 Linux 系统使用一个名为 [Bash（Bourne Again Shell）](https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html) 的程序作为与操作系统交互的 Shell 程序。Bash 是 [sh](https://man7.org/linux/man-pages/man1/sh.1p.html) 的增强版，而 sh 是 Unix 系统最初的 Shell 程序。除了 `bash`，还有其他 Shell，包括但不限于 [Zsh](https://en.wikipedia.org/wiki/Z_shell)、[Tcsh](https://en.wikipedia.org/wiki/Tcsh)、[Ksh](https://en.wikipedia.org/wiki/KornShell)、[Fish shell](https://en.wikipedia.org/wiki/Fish_(Unix_shell)) 等等。

我们经常会读到或听到其他人谈论在系统上“获取 shell”（也就是获得命令行级别的访问权限）。这意味着目标主机已被利用，我们已经获得了 shell 级别的访问权限（通常是 `bash` 或 `sh`），并且可以像登录到主机上一样交互式地运行命令。可以通过利用 web 应用程序或网络/服务漏洞来获得 shell，也可以通过获取凭据并远程登录到目标主机来获得 shell。有三种主要类型的 shell 连接：

|   |   |
|---|---|
|**Shell 类型**|**描述**|
|`反向 shell`|向我们攻击盒上的“监听器”发起连接。|
|`绑定 shell`|在目标主机上“绑定”到特定端口，并等待来自我们攻击盒的连接。|
|`Web shell`|通过 web 浏览器运行操作系统命令，通常不是交|

互式的或半交互式的。它也可以用于运行单个命令（即利用文件上传漏洞并上传 `PHP` 脚本来运行单个命令）。 |

每种类型的 shell 都有其使用场景，获取 shell 的助手程序可以用许多语言编写（如 `Python`、`Perl`、`Go`、`Bash`、`Java`、`awk`、`PHP` 等）。这些可以是小型脚本或更复杂的程序，用于在目标主机和我们的攻击系统之间建立连接并获取“shell”访问权限。在后面的章节中将详细讨论 shell 访问权限。

---

## 什么是端口？

可以将 [端口](https://en.wikipedia.org/wiki/Port_(computer_networking)) 视为房子上的窗户或门（房子是远程系统），如果窗户或门未关好或没有上锁，我们通常可以未经授权地进入房子。在计算机中也是如此。端口是网络连接开始和结束的虚拟点。它们是基于软件的，并由主机操作系统进行管理。端口与特定的进程或服务相关联，允许计算机区分不同的流量类型（SSH 流量流向的端口与访问网站的 web 请求流向的端口不同，尽管这些访问请求都通过同一网络连接发送）。

每个端口都被分配一个数字，并且许多端口在所有网络连接的设备上都是标准化的（尽管可以配置服务在非标准端口上运行）。例如，`HTTP` 消息（网站流量）通常发送到端口 `80`，而 `HTTPS` 消息发送到端口 `443`，除非另有配置。我们会遇到在非标准端口上运行的 web 应用程序，但通常会在端口 80 和 443 上找到它们。端口号使我们能够访问运行在目标设备上的特定服务或应用程序。从非常高的层面上讲，端口帮助计算机了解如何处理其接收到的各种数据。

端口分为两类，[传输控制协议（TCP）](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) 和 [用户数据报协议（UDP）](https://en.wikipedia.org/wiki/User_Datagram_Protocol)。 `TCP` 是面向连接的，这意味着在可以发送数据之前，客户端和服务器之间必须建立连接。服务器必须处于监听状态，等待来自客户端的连接请求。 `UDP` 采用无连接通信模型。它没有“握手”，因此会引入一定的不可靠性，因为无法保证数据的传递。当错误校正/检查不是必要的或由

应用程序本身处理时，`UDP` 是有用的。`UDP` 适用于运行时间敏感任务的应用程序，因为丢弃数据包比等待因重传而延迟的数据包更快，而后者是 `TCP` 的情况，并且可能严重影响实时系统。`TCP` 有 `65,535` 个端口，`UDP` 也有 `65,535` 个不同的端口，每个端口由一个数字表示。下面列出了一些最著名的 `TCP` 和 `UDP` 端口：

|   |   |
|---|---|
|端口|协议|
|`20`/`21` (TCP)|`FTP`|
|`22` (TCP)|`SSH`|
|`23` (TCP)|`Telnet`|
|`25` (TCP)|`SMTP`|
|`80` (TCP)|`HTTP`|
|`161` (TCP/UDP)|`SNMP`|
|`389` (TCP/UDP)|`LDAP`|
|`443` (TCP)|`SSL`/`TLS` (`HTTPS`)|
|`445` (TCP)|`SMB`|
|`3389` (TCP)|`RDP`|

作为信息安全专业人员，我们必须能够快速记住大量关于各种主题的信息。对于我们来说，尤其是作为渗透测试人员，快速掌握许多 `TCP` 和 `UDP` 端口，并能够凭借端口号快速识别它们（即知道端口 `21` 是 `FTP`，端口 `80` 是 `HTTP`，端口 `88` 是 `Kerberos`）而无需查阅资料是很重要的。这将随着实践和重复而提升，并最终成为我们攻击更多的目标、实验室和真实网络时的第二天性，帮助我们更高效地工作并更好地优先考虑枚举工作和攻击。

类似 [这个](https://www.stationx.net/common-ports-cheat-sheet/) 和 [这个](https://packetlife.net/media/library/23/common-ports.pdf) 的指南是学习标准和不常见的 TCP 和 UDP 端口的好资源。挑战自己尽可能多地记住这些内容，并对上述表中列出的每个协议进行一些研究。这是 `nmap` 扫描的前 1000 个 `TCP` 和 `UDP` 端口的一个很好的 [参考](https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/)，以及 `nmap` 扫描的前 100 个服务。

---

## 什么是 Web 服务器

Web 服务器是运行在后端服务器上的应用程序，负责处理来自客户端浏览器的所有流量。将其路由到请求的目标页面，并最终向客户端浏览器做出响应。Web 服务器通常在 80 或者 443 端口上运行。并负责将最终用户连接到 web 应用程序的各个部分，以及处理它们的各种响应。

由于 web 应用程序往往对公众开放并面向互联网，如果它们存在任何漏洞，可能会导致后端服务器被攻击者入侵。Web 应用程序可以提供广泛的攻击面，使其成为攻击者和渗透测试人员的高价值目标。

许多类型的漏洞可能影响 Web 应用程序。我们经常会听到/看到对 [OWASP Top 10](https://owasp.org/www-project-top-ten/) 的提及。这是由开放 Web 应用安全项目（OWASP）维护的顶级 10 个 Web 应用程序漏洞的标准化清单。该清单被认为是最危险的 10 个漏洞，但不是所有可能的 Web 应用程序漏洞的详尽清单。Web 应用程序安全评估方法通常以 OWASP Top 10 作为起点，用于检查应该检查的顶级漏洞类别。当前的 OWASP Top 10 清单如下：

|   |   |   |
|---|---|---|
|编号|类别|描述|
|1.|[破坏的访问控制](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)|未正确实施限制，以防止用户访问其他用户的帐户、查看敏感数据、访问未经授权的功能、修改数据等。|
|2.|[加密失败](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)|与加密相关的失败，通常导致敏感数据暴露或系统被入侵。|
|3.|[注入](https://owasp.org/Top10/A03_2021-Injection/)|应用程序未对用户提供的数据进行验证、过滤或清理。注入的一些示例包括 SQL 注入、命令注入、LDAP 注入等。|
|4.|[不安全的设计](https://owasp.org/Top10/A04_2021-Insecure_Design/)|当应用程序没有考虑安全性时出现的问题。|
|5.|[安全配置错误](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)|缺少适当的安全加固，包括应用程序堆栈的任何部分、不安全的默认配置、开放的云存储、透露太多信息的详细错误消息等。|
|6.|[易受攻击的和过时的组件](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)|使用易受攻击、不受支持或过时的组件（包括客户端和服务器端）。|
|7.|[身份验证和认证失败](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)|针对用户的身份、认证和会话管理的身份验证相关攻击。|
|8.|[软件和数据完整性失败](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)|软件和数据完整性失败与不保护完整性违规的代码和基础设施相关。一个例子是应用程序依赖于来自不可信来源、存储库和内容分发网络（CDN）的插件、库或模块。|
|9.|[安全日志记录和监控失败](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)|此类别旨在帮助检测、升级和响应主动入侵。没有日志记录和监控，无法检测入侵。|
|10.|[服务器端请求伪造](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)|当 Web 应用程序在未验证用户提供的 URL 的情况下获取远程资源时发生 SSRF 漏洞。它允许攻击者强制应用程序向意外的目标发送精心构造的请求，即使受到防火墙、VPN 或其他类型的网络访问控制列表（ACL）的保护也是如此。|

熟悉这些类别及其相关的各种漏洞非常重要。后续模块将深入介绍 Web 应用程序漏洞。要了解有关 Web 应用程序的更多信息，请参阅 [Introduction to Web Applications](https://academy.hackthebox.com/module/details/75) 模块。