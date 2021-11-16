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

命令行没大变动。

另外，没有配置文件时，req 命令的报错 `unable to find 'distinguished_name' in config`
openssl 3 不报错了。
```bash
openssl req -config /dev/null -new -keyout demo.key -out demo.csr -subj '/CN=demo' -nodes

```

## CeontOS 8 源码编译安装 openssl
2021-11-09
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
