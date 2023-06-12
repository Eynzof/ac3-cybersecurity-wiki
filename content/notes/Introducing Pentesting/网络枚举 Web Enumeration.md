```
title: 网络枚举 Web Enumeration
```

在进行服务扫描时，我们经常会遇到在端口80和443上运行的Web服务器。Web服务器托管Web应用程序（有时超过1个），这些应用程序通常提供了很大的攻击面，并且在渗透测试中是非常高价值的目标。正确的Web枚举至关重要，特别是当组织没有暴露许多服务或这些服务被适当地修补时。

## Gobuster

在发现Web应用程序后，我们可以检查是否可以发现Web服务器上未经公开访问的隐藏文件或目录。我们可以使用诸如[ffuf](https://github.com/ffuf/ffuf)或[GoBuster](https://github.com/OJ/gobuster)之类的工具来执行此目录枚举。有时我们会发现隐藏的功能或暴露敏感数据的页面/目录，这些可以用于访问Web应用程序甚至在Web服务器本身上执行远程代码执行（RCE）。

#### 目录/文件枚举

GoBuster是一个多功能工具，可以执行DNS、虚拟主机和目录爆破。该工具还具有其他功能，例如列举公共的AWS S3存储桶。对于本模块的目的，我们对使用`dir`选项指定的目录（和文件）爆破模式感兴趣。让我们使用`dirb` `common.txt`字典运行一个简单的扫描。

目录/文件枚举

```Plaintext
jw0610a@htb[/htb]$ gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.121/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/11 21:47:25 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/index.php (Status: 200)
/server-status (Status: 403)
/wordpress (Status: 301)
===============================================================
2020/12/11 21:47:46 Finished
===============================================================
```

HTTP状态码为`200`表示请求的资源成功，而403 HTTP状态码表示我们被禁止访问该资源。301状态码表示我们正在重定向，这不是一个失败的情况。值得熟悉各种HTTP状态码，可以在[这里](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)找到。`Web Requests` Academy 模块还更详细

地介绍了HTTP状态码。

扫描成功完成，它在`/wordpress`发现了一个WordPress安装。WordPress是最常用的内容管理系统（CMS），具有巨大的潜在攻击面。在这种情况下，通过在浏览器中访问`http://10.10.10.121/wordpress`，我们发现WordPress仍处于设置模式，这将允许我们在服务器上获得远程代码执行（RCE）。

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjM3NGI0YTliNTExZGJiODY4OGJiN2NmZmEwMmM0ZjJfdFBkMWd6VjFFM2hvQUxQZ296SXB4dlpkN2VjSHo1VGNfVG9rZW46UVJVd2JzaXRjb3VuaEx4ZlVsVWNNSmJMblFiXzE2ODY0OTU2OTQ6MTY4NjQ5OTI5NF9WNA)

#### DNS子域名枚举

还可能有重要的资源托管在子域上，例如管理员面板或具有附加功能的应用程序，这些应用程序可能会受到利用。我们可以使用`GoBuster`来枚举给定域的可用子域，使用`dns`标志指定DNS模式。首先，让我们克隆SecLists GitHub [repo](https://github.com/danielmiessler/SecLists)，其中包含许多用于模糊和利用的有用列表：

#### 安装SecLists

```Plaintext
jw0610a@htb[/htb]$ git clone https://github.com/danielmiessler/SecLists
```

```Plaintext
jw0610a@htb[/htb]$ sudo apt install seclists -y
```

然后，将DNS服务器（例如1.1.1.1）添加到`/etc/resolv.conf`文件中。我们将以一个虚构的货运和物流公司的网站域`inlanefreight.com`为目标。

安装SecLists

```Plaintext
jw0610a@htb[/htb]$ gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Domain:     inlanefreight.com
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/SecLists/Discovery/DNS/namelist.txt
===============================================================
2020/12/17 23:08:55 Starting gobuster
===============================================================
Found: blog.inlanefreight.com
Found: customer.inlanefreight.com
Found: my.inlanefreight.com
Found: ns1.inlanefreight.com
Found: ns2.inlanefreight.com
Found: ns3.inlanefreight.com
===============================================================
2020/12/17 23:10:34 Finished
===============================================================
```

这次扫描揭示了几个有趣的子域，我们可以进一步检查。[Attacking Web Applications with Ffuf](https://academy.hackthebox.com/module/details/54) 模块详细介绍了Web枚举和模糊的更多细节。

---

## Web枚举提示

让我们通过一些额外的Web枚举提示，帮助完成HTB上的机器和现实世

界中的工作。

#### 横幅抓取/ Web服务器头

在上一节中，我们讨论了横幅抓取的一般目的。Web服务器头提供了一个关于Web服务器托管内容的很好的图片。它们可以揭示使用的具体应用程序框架、身份验证选项以及服务器是否缺少重要的安全选项或已被错误配置。我们可以使用`cURL`从命令行检索服务器头信息。`cURL`是我们渗透测试工具包中的另一个重要工具，熟悉其许多选项是值得鼓励的。

横幅抓取/ Web服务器头

```Plaintext
jw0610a@htb[/htb]$ curl -IL https://www.inlanefreight.com

HTTP/1.1 200 OK
Date: Fri, 18 Dec 2020 22:24:05 GMT
Server: Apache/2.4.29 (Ubuntu)
Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
Link: <https://www.inlanefreight.com/>; rel=shortlink
Content-Type: text/html; charset=UTF-8
```

另一个方便的工具是[EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)，它可以用于对目标Web应用程序进行截图、指纹识别和识别可能的默认凭据。

#### Whatweb

我们可以使用命令行工具`whatweb`提取Web服务器、支持的框架和应用程序的版本。这些信息可以帮助我们确定使用的技术，并开始寻找潜在的漏洞。

Whatweb

```Plaintext
jw0610a@htb[/htb]$ whatweb 10.10.10.121

http://10.10.10.121 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[license@php.net], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.121], Title[PHP 7.4.3 - phpinfo()]
```

`Whatweb`是一个方便的工具，包含许多功能，可以自动化对网络中的Web应用程序进行枚举。

Whatweb

```Plaintext
jw0610a@htb[/htb]$ whatweb --no-errors 10.10.10.0/24

http://10.10.10.11 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.1], IP[10.10.10.11], PoweredBy[Red,nginx], Title[Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux], nginx[1.14.1]
http://10.10.10.100 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.100], Title[File Sharing Service]
http://10.10.10.121 [200 OK] Apache[2.4.

41], Country[RESERVED][ZZ], Email[license@php.net], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.121], Title[PHP 7.4.3 - phpinfo()]
http://10.10.10.247 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@cross-fit.htb], Frame, HTML5, HTTPServer[OpenBSD httpd], IP[10.10.10.247], JQuery[3.3.1], PHP[7.4.12], Script, Title[Fine Wines], X-Powered-By[PHP/7.4.12], X-UA-Compatible[ie=edge]
```

#### 证书

如果使用了HTTPS，SSL/TLS证书是另一个潜在的有价值的信息源。浏览到`https://10.10.10.121/`并查看证书，将显示以下详细信息，包括电子邮件地址和公司名称。如果这在评估的范围内，这些信息可能被用于进行钓鱼攻击。

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=OTY2ZTBiY2ZjYjVmNGVjMDJhYjdlNDYzZTU3MTBlMjBfcjJ3MHVUM0VsUFhxSnkyN2ZMeFpqQ0E2dlRCTzYyRjFfVG9rZW46RlRObWJaTXRKb04xaWJ4UjNZTGNBNU4xbmVNXzE2ODY0OTU2OTQ6MTY4NjQ5OTI5NF9WNA)

#### Robots.txt

网站通常包含一个`robots.txt`文件，其目的是指示搜索引擎网络爬虫（如Googlebot）可以和不可以访问的资源进行索引。`robots.txt`文件可以提供有价值的信息，例如私有文件和管理员页面的位置。在这种情况下，我们可以看到`robots.txt`文件包含两个禁止访问的条目。

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=MGQwMzFjYzMzN2JhMjVmMThkNWM2M2Q2M2Y2MDE4ZjFfVU85MENhWFdvTERRV011bkhnbGI1Z2pvQU4zM2NtRmlfVG9rZW46SXlXTGJvVUE0bzl3WUF4UnplNGNzSUJybjFjXzE2ODY0OTU2OTQ6MTY4NjQ5OTI5NF9WNA)

在浏览器中导航到`http://10.10.10.121/private`将显示一个HTB管理员登录页面。

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=YjYxMzQ1OTVlMTFhN2IzMDk1NTdiMGVjMzVkZjkzZThfQlVPM3h1ckZTSHNTUlVOMnQwODRIblJaMm5uZXdtOGNfVG9rZW46Q2J1T2JUZFNsb2tqamp4dDJqUWNTZWNPbjJnXzE2ODY0OTU2OTQ6MTY4NjQ5OTI5NF9WNA)

#### 源代码

还值得检查我们遇到的任何网页的源代码。我们可以使用`[CTRL + U]`组合键在浏览器中打开源代码窗口。这个例子显示了一个包含测试帐户凭据的开发人员注释，这些凭据可以用于登录网站。

![](https://gwmah9jwtul.feishu.cn/space/api/box/stream/download/asynccode/?code=ZWNjYTE5NmJmMjRhMDIwYWMxNDY2ZDdkOGM2ODcxMTVfTktHY0NYeGo1OHVyeGU0N0hqVnQ4WVJyQ2lTODc1S05fVG9rZW46TlFJSGJJdVhtb2lOa1d4akZTRmNiM1hzbkdlXzE2ODY0OTU2OTQ6MTY4NjQ5OTI5NF9WNA)