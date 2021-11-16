---
title: openssl 命令行学习笔记
date: 2021-11-14
---

# openssl 基础
OpenSSL 是一个开源项目，其组成主要包括一下三个组件：
- openssl：多用途的命令行工具
- libcrypto：加密算法库
- libssl：加密模块应用库，实现了ssl及tls

openssl可以实现：秘钥证书管理、对称加密和非对称加密。

- [Secure Salted Password Hashing - How to do it Properly](https://crackstation.net/hashing-security.htm)
- [OpenSSL官网](https://www.openssl.org/)
- [openssl用法详解](https://www.cnblogs.com/yangxiaolan/p/6256838.html)

2020年2月16日

openssl version
OpenSSL 1.1.1d  10 Sep 2019

## 配置文件的位置
许多命令支持从配置文件读取部分或全部的参数，用 -config 选项指定配置文件，或者
用环境变量 OPENSSL_CONF。如果既没有指定 -config 也没有设置 OPENSSL_CONFIG 变量，、
则使用默认路径下的 openssl.conf 文件作为配置文件，默认路径在编译时指定，
使用 `openssl version -d` 确认默认配置路径。
