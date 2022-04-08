---
layout:     post
title:      Wargames-Bandit
subtitle:   linux命令学习
date:       2022-03-27
author:     Sprint#51264
header-img: img/post-bg-universe.jpg
catalog: true
tags:
    - Linux命令

---

# 引言

学习linux命令基础，wargames-Bandit
>https://overthewire.org/wargames/bandit/bandit0.html

[linux命令大全菜鸟教程](https://www.runoob.com/linux/linux-command-manual.html)

[Linux命令](http://linux.51yip.com/search/xxd)

>[参考博客](https://blog.csdn.net/winkar/article/details/38408873)

>[参考博客2](http://dljz.nicethemes.cn/news/show-33357.html)

# level 0

* ssh
    
    * 概念
        
        安全外壳(secure shell)协议，是较可靠，专为远程登录会话和其他网络服务提供安全性的协议。利用 SSH 协议可以有效防止远程管理过程中的信息泄露问题
    
    * 用法

        `ssh 用户名@xxx.net -p 端口 `

* 步骤

    ```
    ssh bandit0@bandit.labs.overthewire.org -p 2220
    bandit0 

    cat readme  
    #boJ9jbbUNNfktd78OOpsqOltutMc3MY1
    ```      

# level 1

* find

    `find 路径 -参数 "关键字" `

    ``` 
    -user 所有者
    -group 所在组
    -size n : 文件大小 是 n 单位，b 代表 512 位元组的区块，c 表示字元数，k 表示 kilo bytes，w 是二个位元组。

    ```

    查找相关文件位置

* 步骤

    ``` 
    find / -name "-"
    cat /home/bandit1/-

    CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
    ```

# level 2

>文件名带空格读取

* 方法

    >------使用\加空格即'\ '来表示空格------

    ``` 
    cat ./my\ file

    cat /home/bandit2/spaces\ in\ this\ filename
    #不然系统就会认为是分开的好几个文件
    cat: in: No such file or directory
    cat: this: No such file or directory
    cat: filename: No such file or directory
    ```

    >---------使用引号---------

    ``` 
    cat /home/bandit2/'spaces in this filename'
    ```


* 结果

    `UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK`


# level 3

>隐藏文件读取

* ls

    ``` 
    ls -al 查看所有文件

    -a参数do not ignre entries starting with .

    不忽略隐藏文件

    第二列表示链接数，表示有多少个文件链接到inode号码。
    第三列表示拥有者
    第四列表示所属群组
    第五列表示文档容量大小，单位字节
    第六列表示文档最后修改时间，注意不是文档的创建时间哦
    第七列表示文档名称。以点(.)开头的是隐藏文档
    ```

* 步骤

    ``` 
    cd /home/bandit3/inhere
    ls -al

    cat ./.hidden

    pIwrPrtPN36QITSp3EQaw936yaFoFgAB

    ```


# level 4

>从一堆乱码文件中找到有正确结果的文件

* less

    less命令一个一个看吧

    ``` 
    less ./-file00

    以此类推

    #koReBOKuIDDepwhWk7jZC0RTdopnAYKh
    ```

# level 5

>指定文件是易读的、1033bytes、不可执行文件

* du

    >磁盘管理命令
    ``` 
    -a或-all 显示目录中个别文件的大小。
    -b或-bytes 显示目录或文件大小时，以byte为单位。
    -m或--megabytes 以1MB为单位。
    -c或--total 除了显示个别目录或文件的大小外，同时也显示所有目录或文件的总和。

    ```

* 方法

    ``` 
    du -a -b |grep 1033

    显示所有文件大小以bytes为单位并用正则匹配1033bytes大小的文件

    #1033    ./maybehere07/.file2

    cat ./maybehere07/.file2

    #DXjZPULLxYr17uwoI01bNLQbtFemEgo7

    ```

# level 6

>所有者bandit7;所在组bandit6;33 bytes in size;文件名somewhere on the server

* grep

    ``` 
    -v 或 --invert-match : 显示不包含匹配文本的所有行。

    -n 显示行号

    ```

* 步骤

    ``` 
    find / -user 'bandit7' -group 'bandit6' -size 33c | grep -v denied

    # -user所有者 -group 所在组 -size 文件大小 -c 单位bytes

    /var/lib/dpkg/info/bandit7.password

    #HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
    ```

# level 7

>当前目录下有一个data.txt，密码在millionth这个单词旁边

* 步骤

    ``` 
    cat data.txt|grep millionth

    #millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV
    ```

# level 8

>在data.txt文件中只出现了一次的那一行就是密码

* sort

    `sort` 可针对文本文件的内容，以行为单位来排序。

    ``` 
    -b 忽略每行前面开始出的空格字符。
    -c 检查文件是否已经按照顺序排序。
    -d 排序时，处理英文字母、数字及空格字符外，忽略其他的字符。
    -f 排序时，将小写字母视为大写字母。
    -i 排序时，除了040至176之间的ASCII字符外，忽略其他的字符。
    -m 将几个排序好的文件进行合并。
    -n 依照数值的大小排序。
    -u 意味着是唯一的(unique)，输出的结果是去完重了的。
    -o<输出文件> 将排序后的结果存入指定的文件。
    -r 以相反的顺序来排序。
    -t<分隔字符> 指定排序时所用的栏位分隔字符。
    +<起始栏位>-<结束栏位> 以指定的栏位来排序，范围由起始栏位到结束栏位的前一栏位。
    --help 显示帮助。
    --version 显示版本信息。
    [-k field1[,field2]] 按指定的列进行排序。

    #注意，-u只是去重，而不是显示没有重复的项
    ```

* uniq

    >Linux uniq 命令用于检查及删除文本文件中重复出现的行列，一般与 sort 命令结合使用。

    ``` 
    -c或--count 在每列旁边显示该行重复出现的次数。
    -d或--repeated 仅显示重复出现的行列。
    -f<栏位>或--skip-fields=<栏位> 忽略比较指定的栏位。
    -s<字符位置>或--skip-chars=<字符位置> 忽略比较指定的字符。
    -u或--unique 仅显示出一次的行列。
    -w<字符位置>或--check-chars=<字符位置> 指定要比较的字符。
    --help 显示帮助。
    --version 显示版本信息。

    ```

* 步骤

    ``` 
    cat data.txt |sort| uniq -u

    #UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
    ```

# level 9

>密码之前有等于号

* strings

    ``` 
    print the strings of printable characters in files.

    在对象文件或二进制文件中查找可打印的字符串。字符串是4个或更多可打印字符的任意序列，以换行符或空字符结束。 strings命令对识别随机对象文件很有用。

    ```

* 步骤

    ``` 
    cat data.txt |strings|grep =

    #truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk

    ```

# level 10

>data.txt 文件中有base64编码密码

* base64

    ``` 
    使用 Base64 编码/解码文件或标准输入输出。

    -d, --decode          解码数据
    -i, --ignore-garbag   解码时忽略非字母字符
    -w, --wrap=字符数     在指定的字符数后自动换行(默认为76)，0 为禁用自动换行

    ```

* 步骤

    ``` 
    cat data.txt|base64 -d

    #The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR

    ```

# level 11

>data.txt中的密码使用rot13移位加密了所有字母

* tr

    >tr 命令用于转换或删除文件中的字符
    ``` 

    tr [-cdst][--help][--version][第一字符集][第二字符集] 

    ```

* 步骤

    ``` 
    cat data.txt|tr [a-z] [n-za-m]|tr [A-Z] [N-ZA-M]

    #The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu

    ```

# level 12

>data.txt中的内容是压缩文件的十六进制内容

* xxd

    >xxd 命令用于用二进制或十六进制显示文件的内容，如果没有指定outfile参数，则把结果显示在屏幕上，如果指定了outfile则把结果输出到 outfile中；如果infile参数为 – 或则没有指定infile参数，则默认从标准输入读入。

    ``` 
    -r 逆向操作: 把xxd的十六进制输出内容转换回原文件的二进制内容。
    
    -p 以 postscript的连续十六进制转储输出，这也叫做纯十六进制转储
    
    ```

* 步骤

    ``` 
    将data.txt复制到/tmp/temp路径下，因为原路径没有权限，但是要注意的是/tmp普通用户没有可读权限，但是有可写可执行权限

    cp /home/bandit12/data.txt /tmp/test

    xxd -r data.txt data #逆向解析文件中的十六进制内容恢复为指定文件

    file data #获取data文件类型

    mv data data.gz#第一次解压

    file data #第二次分析文件类型
    #bzip2 compressed data, block size = 900k

    以此类推......

    直到
    #data: ASCII text

    mv data data.txt
    cat data.txt

    #The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL

    ```
    ``` 
    这仅仅只是一个开始，接下来每一步需要做的事情是，根据文件头判断它是什么类型的压缩文件。Linux常见的文件包有三种，gnuzip压缩的.gz文件；bzip2压缩的.bz2文件；tar打包的.tar文件。

    $ xxd data | head

    查看其文件头，0x1f8b开头的为gzip文件，注意先将文件名重命名出.gz后缀
    $ gzip -d data.gz

    若文件头为0x425a则为bz2文件，重命名为.bz2

    $bzip2 -d data.bz2

    否则为tar文件，重命名为.tar

    $ tar -xvf data.tar
    ————————————————
    版权声明：本文为CSDN博主「陈文青」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
    原文链接：https://blog.csdn.net/winkar/article/details/38408873

    ```
   
# level 13

>SSH私钥证书登录

* ssh

    `ssh -i 用户名@登录机器`使用ssh私钥登录

* 步骤

    ``` 
    ssh -i ./sshkey.private bandit14@localhost

    cat /etc/bandit_pass/bandit14

    # 4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e

    ```

# level 14

* nc

    ``` 
    echo 4wcYUJFw0k0XLShlDzztnTBHiqxU3b3|nc localhost 30000

    #BfMYroe26WYalil77FoDi9qh59eK5xNr
    ```


# level 15

* OpenSSL

    * 概念

        SSL（secure sockets layer）安全套接层协议，Internet上可以提供秘密性传输，能使用户/服务器应用间的通信不被攻击者窃听，并且始终对服务器进行认证(可选择对用户进行认证)

    * 使用

        ``` 
        openssl s_client -connect xxxx:xxx

        cluFn7wTiGryunymYOu4RcffSxQluehd
        ```

# level 16

>本地31000-32000开了一个SSL端口，将本关密码传进去就能获得下一关密码

* nmap扫描

* 步骤

    ``` 
    nmap localhost -p 31000-32000

    31046/tcp open  unknown
    31518/tcp open  unknown
    31691/tcp open  unknown
    31790/tcp open  unknown
    31960/tcp open  unknown

    openssl一个一个试到31790

    -----BEGIN RSA PRIVATE KEY-----
    MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
    imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
    Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
    DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
    JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
    x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
    KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
    J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
    d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
    YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
    vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
    +TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
    8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
    SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
    HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
    SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
    R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
    Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
    R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
    L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
    blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
    YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
    77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
    dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
    vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
    -----END RSA PRIVATE KEY-----

    ```

    得到一串ssh密钥，还需要用私钥登录

    ``` 
    touch 111.private
    vi 111.private

    #可能显示太开放
    chmod 700 111.private

    ssh -i ./111.private bandit17@localhost

    ```

# level 17

>下一关的密码在passwords.new中两文件的不同行

* diff

    比较两个文件的不同

* 步骤

    ``` 

    diff password.new password.new

    ```


# level 18

>下一关密码在/home的readme中，不幸的是，.bashrc被更改了，用ssh登录就会退出，所以得登陆的时候就执行命令

* 步骤

    ``` 
    连接就会断开，但是不影响命令的执行，先前想的是用管道符能不能命令执行，试了试发现emm，管道符连接后执行的命令是在本地呀，于是乎不用管道符，直接连接命令执行(前提是有权限读取，前几关看过readme权限，任意用户都是可读的)

    ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme


    #IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
    ```

# level 19

>use setuid，要访问下一个级别，您应该在主目录中使用setuid二进制文件
>[参考](https://blog.csdn.net/chest_/article/details/101123204)

* setuid setgid

    set user ID ,set group ID
    允许用户分别以可执行文件所有者或组的文件系统权限运行可执行文件，并更改目录中的行为. 它们通常用于允许计算机系统上的用户以`临时`提升的权限运行程序，`以执行特定任务`。虽然提供的假定用户 ID 或组 ID 权限并不总是提升，但至少它们是特定的。

    >设置setuid的方法是使用Linux的chmod指令，我们都习惯给予一个文件类似“0750” “0644” 之类的权限，它们的最高位0就是setuid的位置, 我们可以通过将其设为4来设置setuid位。（tips：设置为2为setgid，同setuid类似，即赋予文件所在组的权限）

* 步骤

    ``` 
    ls-al 

    #-rwsr-x---  1 bandit20 bandit19 7296 May  7  2020 bandit20-do

    发现对于拥有者有一个s权限

    ./bandit20-do cat /etc/bandit_pass/bandit20

    #GbKksEFF4yrVs6il55v6gwY5aVje5f0j
    ```

# level 20

>主页有一个setuid二进制文件，可以连接到指定的端口，读取一行

>先用nc开一个端口输入待传信息，再用suconnect连接并且读取一行就可以将这行读取，如果相同的话就会传回下一关密码

* 步骤

    ``` 
    echo GbKksEFF4yrVs6il55v6gwY5aVje5f0j | nc -l -p 33333
    #打开端口并且放入一行信息

    新开一个shell
    ./suconnect 33333

    #gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr

    ```

# level 21

>cron是一个定时执行脚本的工具

* 存疑

    ``` 
    cat /usr/bin/cronjob_bandit22.sh 显示没有权限

    #-rwxr-x--- 1 bandit22 bandit21 130 May  7  2020 /usr/bin/cronjob_bandit22.sh
    ```

* 步骤

    >https://blog.csdn.net/weixin_43220691/article/details/119764079

    ``` 
    bandit21@bandit:/etc/cron.d$ cat cronjob_bandit22
    @reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
    bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null

    bandit21@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit22.sh
    #!/bin/bash
    chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
    cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

    bandit21@bandit:/etc/cron.d$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
    Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI

    ```

# level 22

>同样有一个脚本，阅读

* 步骤

    ``` 
    cat cronjob_bandit23
    cat /usr/bin/cronjob_bandit23.sh

    #!/bin/bash

    myname=$(whoami)
    mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

    echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

    cat /etc/bandit_pass/$myname > /tmp/$mytarget

    #把I am user bandit23 md5sum一下再切割取第一列，打开对应文件就会有内容

    #/tmp/8ca319486bfbbc3663ea0fbe81326349

    cat /tmp/8ca319486bfbbc3663ea0fbe81326349

    #jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n

    ```

# level 23

>这关需要自己写一个脚本，运行一次就会消失的，记得保存一下代码

>https://blog.csdn.net/winkar/article/details/38408873----->需要注意的是，用于写入的这个文件必须是一个bandit24拥有写权限的文件，我一开始因为指定了一个已经存在但没有写权限的文件，挣扎了很久都读不出结果。而/dev/null吃掉了所有的错误提示，更加需要自己的谨慎。

* stat

    显示文件或文件系统的状态

* 步骤

    ``` 
    #!/bin/bash

    myname=$(whoami)

    cd /var/spool/$myname
    echo "Executing and deleting all scripts in /var/spool/$myname:"
    for i in * .*;
    do
        if [ "$i" != "." -a "$i" != ".." ];
        then
            echo "Handling $i"
            owner="$(stat --format "%U" ./$i)"
            if [ "${owner}" = "bandit23" ]; then
                timeout -s 9 60 ./$i
            fi
            rm -f ./$i
        fi
    done

    脚本

    #!/bin/bash
    cat /etc/bandit_pass/bandit24 > /tmp/pass24 && chmod 777 /tmp/pass24
    

    #UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ

    ```

# level 24

>这关需要自己写一个脚本，传这一关密码和四位数字给指定端口就可以得到下一关密码

* 代码

    ``` 
     #!/bin/bash         
    a="UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ"
    b=0                                 

    while (($b < 10000))
    do   
        printf "$a %04d\n" $b >> pass5
            let "b++"
        done
      
    cat pass5|nc localhost 30002 >as02

    ```

* 结果

    ``` 
    cat as02

    Wrong! Please enter the correct pincode. Try again.
    Wrong! Please enter the correct pincode. Try again.
    Correct!
    The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

    ```

# level 25

>shell不是/bin/bash

* /etc/passwd

    >https://blog.csdn.net/liukaitydn/article/details/83046083
    * 文件格式
        
        在该文件中，每一行用户记录的各个数据段用“：”分隔，分别定义了用户的各方面属性。各个字段的顺序和含义如下： 

　　    注册名：口令：用户标识号：组标识号：用户名：用户主目录：命令解释程序 

    * 具体解释

        注册名：用来区分不同用户，通常为一，长度8个字符之内且在linux中大小写敏感

        口令：系统用口令验证用户合法性，现在的unix/linux系统中，用户的口令通常保存在/etc/shadow文件中，而passwd文件中用x代替密码，需要注意的是，如果passwd字段中第一个字符是"*"的话，就表明该账号被查封了，系统不允许持有该账号的用户登录

        用户标识号(UID)：唯一用户标识，区别用户。
        
        组标识号(GID)

        用户名(user_name)

        用户主目录(home_directory)：该字段定义了个人用户得主目录，当用户登陆后，他的Shell将把该目录作为用户的工作目录。

        命令解释程序(Shell)：Shell是当用户登陆系统是运行的程序名称，通常是一个Shell程序得全路径名
    
    * vi

        在vi中参数
        :!{cmd} 「 执行cmd命令 」
        :r[ead] !{cmd} 「 输出到缓冲区」
        可以执行命令

        more命令下可以使用vi参数、！参数，前提是当前屏幕不能完全显示内容。因此将命令窗口调小，然后就可以通过v进入vi界面，然后输入

* 步骤

    ``` 
    https://blog.csdn.net/liukaitydn/article/details/83046083

    cat /etc/passwd

    #bandit26:x:11026:11026:bandit level 26:/home/bandit26:/user/bin/showtext

    cat /usr/bin/showtext

    #!bin/sh
    
    export TERM=linux

    more ~/text.txt
    exit0


    使用~目录下的sshkey文件登录bandit26账号，就会看到输出了text.txt文件里的内容

    将窗口调小，在用私钥登录之后直接按v键进入vi界面，通过:r /etc/bandit_pass/bandit26执行命令

    #5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z
    ```

# level 26

>上一关说明了，这个26关shell是/showtext，输出信息之后就会退出登录。所以登录之后同上关，调窗口，v进入vi进行设置

>[vi-vim （十四）：shell命令](https://www.cnblogs.com/smstars/archive/2013/05/18/3085347.html)
>[vi set用法-vi set命令](https://blog.csdn.net/weixin_34235105/article/details/93042762)

* vi

    ``` 
    :!command 暂停vi，执行指定的shell命令
    :sh 暂停vi，启动一个新的shell
    :set显示所有的vi环境变量设置

    n!! command 对n行数据执行command
    !move command 对当前光标至move所指定的位置的数据执行command
    !move fmt 格式化当前光标到move所指的行

    
    ```

* steps

    ``` 
    缩小命令窗口，拖成一个角角，ssh登录，

    登陆后按v键(窗口要够小，不然more命令全输出就退出登录了)

    :set shell=/bin/bash #设置vi环境为bin/bash
    :sh #再起一个shell

    ./bandit27-do cat /etc/bandit_pass/bandit27

    #3ba3118a22e93127a4ed485be72ef5ea

    ```


# level 27

>git的使用,git用户和bandit27密码相同

* steps

    ``` 
    cd /tmp
    mkdir test

    cd test
    git clone ssh://bandit27-git@localhost/home/bandit27-git/repo

    输密码:3ba3118a22e93127a4ed485be72ef5ea

    cd repo
    cat README

    #The password to the next level is: 0ef186ac70e04ea33b4c1853d2526fa2

    ```

# level 28

>git历史版本查看
>http://linux.51yip.com/search/git

* git

    ``` 
    git revert 还原一个版本的修改，必须提供一个具体的版本号，git revert bbaf6fb5060b4875b18ff9ff637ce118256d6f20

    git branch：对分支的增、删、查等操作，例如'git branch new_branch'会从当前的工作版本创建一个叫做new_branch的新分支，'git branch -D new_branch'就会强制删除叫做new_branch的分支，'git branch'就会列出本地所有的分支

    git log：查看历史日志，该功能类似于SVN的log

    git show可以用于显示提交日志的相关信息（以不同格式或信息量的多少）。

    git checkout Git的checkout有两个作用，其一是在不同的branch之间进行切换，例如'git checkout new_branch'就会切换到new_branch的分支上去；另一个功能是还原代码的作用，例如'git checkout app/model/user.rb'就会将user.rb文件从上一个已提交的版本中更新回来，未提交的内容全部会回滚

    ```

* steps

    ``` 
    cd /tmp
    mkdir test
    git clone ssh://bandit28-git@localhost/home/bandit28-git/repo

    cd repo

    cat README.txt

    #发现password全被掩盖了

    用git log看一看历史版本，发现最新的是 fix info leak修复信息泄露

    用git show就可以查看更改的信息

    - username: bandit29
    -- password: bbc96594b4e001778eee9975372716b2
    +- password: xxxxxxxxxx


    ```

# level 29

>看分支

* steps

    ``` 
    clone下来之后发现文件密码写着no passwords in production!

    git log发现历史版本也只是更改了username

    查看分支

    git branch -a

    remotes/origin/HEAD -> origin/master
    remotes/origin/dev
    remotes/origin/master
    remotes/origin/sploits-dev
    
    git checkout dev

    cat README.md

    #- password: 5b90576bedb2cc04c86a9e924ce42faf

    我看过了，code里面有个fig2ascii.py，但是脚本是空的
    ```

# level 30

>[10.3 Git 内部原理 - Git 引用](https://git-scm.com/book/zh/v2/Git-%E5%86%85%E9%83%A8%E5%8E%9F%E7%90%86-Git-%E5%BC%95%E7%94%A8)


* git 引用

    如果我们有一个文件来保存 SHA-1 值，而该文件有一个简单的名字， 然后用这个名字指针来替代原始的 SHA-1 值的话会更加简单。

    在 Git 中，这种简单的名字被称为“引用（references，或简写为 refs）”。
    引用用来标识历史提交位置开头
    Git 分支的本质：一个指向某一系列提交之首的指针或引用

* steps

    ``` 
    git show-ref
    git show refs/tags/secret

    #47e603bb428404d265f59c42920d81e5
    ```


# level 31

>git push

>(参考博客)[https://www.cnblogs.com/baimaoma/p/8939876.html]

* 引用内容

    ``` 
    git add . //由于文件发生了变化所以我们要追踪文件变化特别意不要忘记add后面的点  

    git commit -m "Test" //这里相当于一个注释告诉别人谁做了什么操作

    git push -u origin master //经过上面的操作我们最终要用这个命令来将本地的文件上传到git服务器

    ```


* steps

    ``` 
    新建一个文件夹/tmp/t4

    新建文件key.txt 
        
        File name: key.txt
        Content: 'May I come in?'


    git add -f key.txt

    git commit -m "key.txt"

    git pushs

    #56a9bf19c63d650ce78e6ec0354ee45e

    ```

# level 32

* linux知识

    ``` 
    $$ 
    Shell本身的PID（ProcessID） 
    $! 
    Shell最后运行的后台Process的PID 
    $? 
    最后运行的命令的结束代码（返回值） 
    $- 
    使用Set命令设定的Flag一览 
    $* 
    所有参数列表。如"$*"用「"」括起来的情况、以"$1 $2 … $n"的形式输出所有参数。 
    $@ 
    所有参数列表。如"$@"用「"」括起来的情况、以"$1" "$2" … "$n" 的形式输出所有参数。 
    $# 
    添加到Shell的参数个数 
    $0 
    Shell本身的文件名 
    $1～$n 
    添加到Shell的各参数值。$1是第1参数、$2是第2参数…。

    ```

* steps

    ``` 
    $0 #进入shell

    cat /etc/bandit_pass/bandit33

    #c9c3199ddf4121b10cf581a98d51caee


    ```


# 小彩蛋

>淦，git关卡29，创建test文件夹的时候发现每关创建的test都在，索性直接用test+关卡命名文件夹，没想到test29就是存在的，进去一看，直接有密码哈哈哈哈，看了看其他关也是，捷径捷径，有趣