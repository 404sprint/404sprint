---
layout:     post
title:      Burpsuite使用
subtitle:   bp模块使用方法小结
date:       2020-11-17
author:     Sprint#51264
header-img: img/post-bg-universe.jpg
catalog: true
tags:
    - 工具
---

# 引言


# 配置


# proxy



# spider



# scanner




# intruder

* Sniper

        狙击手，基础爆破，对单一参数进行爆破，如果是两个参数的话，就分别爆破，爆完第一个爆第二个

* Battering ram
        
        攻城锤，如果只有一个参数的话，与Sniper是一样的，但是有两个参数的话，是对两个参数值同时进行爆破，并且值是相同的

* Pitchfork

        必须多参数进行爆破，如果只有单一参数就会报错，如果有两个参数的话就需要添加两个payload

        p1:1,2
        p2:3,4

        并且，第一次爆破为1，3;第二次爆破为2，4

* Cluster bomb

        集束炸弹，两个参数起步，但会计算两个payload的笛卡尔积

        p1:1,2,3
        p2:4,5,6

        那么进行的爆破就是

        第一次:1,4
        第二次:1,5

        爆完1爆2
        以此类推


# repeater



# sequencer



# decoder


# comparer



# extender