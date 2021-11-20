---
description: openssl 的背景知识
prev:
  text: home
  link: /
next:
---
# 关于
## 关于 openssl

### 是什么
OpenSSL 是一个开源项目，其组成主要包括一下三个组件：
- openssl：多用途的命令行工具
- libcrypto：加密算法库
- libssl：加密模块应用库，实现了ssl及tls

openssl可以实现：秘钥证书管理、对称加密和非对称加密。

使用 C 语言开发。是开源、免费的软件。

OpenSSL可以运行在OpenVMS、 Microsoft Windows以及绝大多数类Unix操作系统上（包括Solaris，
Linux，Mac OS X与各种版本的开放源代码BSD操作系统）。

### 版本历史
openssl 以 Eric Young以及Tim Hudson两人开发的SSLeay为基础。

- 0.9.1 	1998.12.23      OpenSSL项目的正式开启
- ……
- 1.0.0   2010.03.29
- 1.0.1   2012.03.14
- 1.0.2   2015.01.22
- 1.1.0   2016.08.25
- 1.1.1   2018.09.11      长期支持版，至 2023.09.11
- 3.0.0   2021.09.07      支持至 2023.09.07

维基百科这里介绍了 openssl 的用途、起源、支持的平台、各个版本的发行时间。

[OpenSSL - 维基百科](https://zh.wikipedia.org/wiki/OpenSSL)

### 版本策略
[/policies/releasestrat.html](https://www.openssl.org/policies/releasestrat.html)

openssl 的版本符合 MAJOR.MINOR.PATCH 的模板，
自 3.0.0 开始证 MAJOR 相同的版本之间，其 API/API 兼容。
而之前的版本保证 MAJOR.MINOR 相同的，其 API/ABI 兼容。

- MAJOR: API/ABI incompatible changes will increase this number
- MINOR: API/ABI compatible feature releases will change this
- PATCH: Bug fix releases will increment this number. We also allow backporting of accessor functions in these releases.

1.0.0 到 1.1.1 （包括1.0.0和1.1.1）之间的版本规则是：
- 字母发行版对于bug修复，如 1.0.2a 修复bug和安全问题，不引入新特性
- PATCH 变化表示引入了新特性，但不破坏兼容性，比如 1.1.0 vs. 1.1.1

可能指定某版本为长期支持版（LTS），长期支持版提供至少 5 年的支持，非长期支持版提供至少 2 年的支持。每个版本支持期的最后一年
只做安全问题的修复，不会提交对 bug 的修复。

### 官网链接
官网 [openssl](https://www.openssl.org/)

## 关于笔记

### 使用的版本
学习 openssl 的时候没关注版本，学完一阶段回头看，是1.1.1i版。
```bash
$ openssl version
OpenSSL 1.1.1i  8 Dec 2020
```
现在（2021-11-20）也发布了 openssl 3.0.0，（2021.09.18发布），只简单尝试了一下。

### 仅对于命令行
openssl 提供了两种接口，命令行工具箱和API接口库，我只是学习命令行工具箱的基本使用。
命令行没有完整覆盖openssl的功能，要使用完整的功能，对openssl的行为进行精确的控制，
需要通过API接口，自己编写程序。
