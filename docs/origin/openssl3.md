# openssl 3.0
2021-11-09

"3.0 正式版发布公告, 2021.09.07"
[OpenSSL 3.0 Has Been Released!](https://www.openssl.org/blog/blog/2021/09/07/OpenSSL3.Final/)

"版本号策略，基本采用 semver 风格"
[/policies/releasestrat.html](https://www.openssl.org/policies/releasestrat.html)

[迁移指南](https://www.openssl.org/docs/man3.0/man7/migration_guide.html)

[在线man手册](https://www.openssl.org/docs/man3.0/man7/crypto.html)

[github仓库](https://github.com/openssl/openssl)

[OpenSSL Cookbook](https://www.feistyduck.com/library/openssl-cookbook/online/ch-openssl.html)


## 与 1.1.1 的区别
不全。

- API接口的接入方式发生了变化
- 命令行好像变化不大
- 版本号的语义发生了变化

openssl 3 修复了`unable to find 'distinguished_name' in config`的报错。
:::details
屏蔽掉配置文件时，调用 req 命令会报错 `unable to find 'distinguished_name' in config`
```bash
openssl req -config /dev/null \
  -new -keyout demo.key \
  -out demo.csr \
  -subj '/CN=demo' -nodes
```

输出
```bash
Generating a RSA private key
.............................................................+++++
....................................+++++
writing new private key to 'demo.key'
-----
unable to find 'distinguished_name' in config
problems making Certificate Request
140101273249152:error:0E06D06C:configuration file routines:NCONF_get_string:no value:../crypto/conf/conf_lib.c:273:group=req name=distinguished_name
```
:::

## CeontOS 8 源码编译安装 openssl
2021-11-09

当前（2021-11-20）常见的操作系统好像的软件库好像还是用的 openssl 1.1.x 版本，要使用 3.0.0，得要自己手动编译安装。

下载解压
```bash
curl --limit-rate 5m -L -o openssl-3.0.0.tar.gz https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.0.tar.gz
tar xzf openssl-3.0.0.tar.gz
```

编译安装：
```bash

./config enable-fips

con=$(($(nproc)+1))
make -sj $con
make -sj $con install
```

某些操作系统预安装了 openssl，此时强烈建议把新版的 openssl 安装到单独的目录下，以免造成破坏。
> On some platforms OpenSSL is preinstalled as part of the Operating System. In this case it is highly recommended not to overwrite the system versions, because other applications or libraries might depend on it. To avoid breaking other applications, install your copy of OpenSSL to a different location which is not in the global search path for system libraries.

```bash

./config --prefix=/opt/openssl --openssldir=/opt/openssl enable-fips

con=$(($(nproc)+1))
make -sj $con
make -sj $con install

echo /opt/openssl/lib64 >> /etc/ld.so.conf && ldconfig
```

编译成静态库
```bash

./config --prefix=/opt/ssl --openssldir=/opt/ssl enable-fips no-shared

make -sj $(($(nproc)+1))
sudo make -sj $(($(nproc)+1)) install

sudo ln -s  /opt/ssl/bin/openssl /usr/local/bin/
```

PS:我对手动编译安装Linux程序只会一些皮毛，又忍不住想尝试一下，怕不小心破坏了其它依赖于 openssl 库的程序的功能，所以
把它编译成静态库，仅供自己尝试。

