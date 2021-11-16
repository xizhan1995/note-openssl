---
descript: openssl 原始笔记，待整理
date: 2021-11-17
---
# note openssl
OpenSSL 是一个开源项目，其组成主要包括一下三个组件：
- openssl：多用途的命令行工具
- libcrypto：加密算法库
- libssl：加密模块应用库，实现了ssl及tls

openssl可以实现：秘钥证书管理、对称加密和非对称加密。

[Secure Salted Password Hashing - How to do it Properly](https://crackstation.net/hashing-security.htm)
[OpenSSL官网](https://www.openssl.org/)

[openssl用法详解](https://www.cnblogs.com/yangxiaolan/p/6256838.html)

2020年2月16日

openssl version
OpenSSL 1.1.1d  10 Sep 2019

## 名字
openssl - OpenSSL 命令行工具

## 语法
```
openssl command [ command_opts ] [ command_args ]

openssl list [ standard-commands | digest-commands | cipher-commands |
cipher-algorithms | digest-algorithms | public-key-algorithms]

openssl no-XXX [ arbitrary options ]
```
根据 openssl help 的输出，可看到命令分为三组：标准命令、摘要命令、密码命令。
同时，摘要命令可由标准命令中的 dgst 统领，密码命令可以由标准命令中的 enc 统领。

## 描述（Description）
OpenSSL是一个密码工具箱，它实现了 SSL（v2/v3）、TSL（v1）以及它们要用到的加密标准。

openssl 程序是 OpenSSL 提供的命令行接口。它可用于：
- 公钥、私钥的创建和管理
- 公钥加密操作
- X.509 证书、CSR、CRL 的创建
- 计算消息摘要
- 用口令加解密数据、文件
- SSL/TLS 客户端与服务的测试
- 处理 S/MIME 签名或加密过的右键
- 时间戳查询、创建和验证

## 命令总览
openssl程序提供了丰富的命令，每个命令有很多选项和参数。大部分命令都有详细的文档和
使用示例。

许多命令支持从配置文件读取部分或全部的参数，用 -config 选项指定配置文件，或者
用环境变量 OPENSSL_CONF。如果既没有指定 -config 也没有设置 OPENSSL_CONFIG 变量，、
则使用默认路径下的 openssl.conf 文件作为配置文件，默认路径在编译时指定，
使用 `openssl version -d` 确认默认配置路径。

list 命令用于列出当前可用的标准命令、实现的算法。

no-XXX 命令测试给定的命令 XXX 是否可用，如果没有，则退出码为0，否则退出值为1，并
输出XXX。这两种情况下，都把内容输出到标准输出，并保证不向stderr输出任何内容。
```sh
$ openssl no-md5
md5
$ openssl no-md6
no-md6
```

找默认配置文件
```bash
# 用包管理工具，把软件包的所有文件名都过滤一遍
$ dpkg -L openssl | grep .cnf
/etc/ssl/openssl.cnf
/usr/lib/ssl/openssl.cnf
$ ll /usr/lib/ssl/openssl.cnf
lrwxrwxrwx 1 root root 20 Jan 30  2021 /usr/lib/ssl/openssl.cnf -> /etc/ssl/openssl.cnf
# 使用 openssl 的命令行接口，更靠谱
$ openssl version -d
OPENSSLDIR: "/usr/lib/ssl"
```

## 配置和选项
对于命令行接口：
1. 所有的配置文件选项都可以通过命令行提供吗？不是的。至少，req 的 distinguished_name 就没有对应的命令行选项。

配置文件语法规则
- man openssl config
配置文件的可用选项
- man openssl ca
- man openssl req
- man openssl x509
## 配置文件
### 说明
主配置文件 openssl.cfg。

Openssl 提供了 CONF 库读取配置文件。

文件分节，每节的开头为 `[ section_name ]`
> A configuration file is divided into a number of sections. Each section starts with a line [ section_name ] and ends when a new section is started or end of
file is reached. A section name can consist of alphanumeric characters and underscores.

第一节比较特殊，它是 default，可以匿名。它的作用是托底。
> The first section of a configuration file is special and is referred to as the default section. This section is usually unnamed and spans from the start of
file until the first named section. When a name is being looked up it is first looked up in a named section (if any) and then the default section.

环境变量映射为 ENV 的节。
> The environment is mapped onto a section called ENV.

井号开头的是注释。

.include 指令可以包含别的文件，甚至可以包含目录，但目录下的文件不可以再包含目录，只能包含文件了。相对路径是相对于程序的当前工作路径而不是相对于配置文件的路径，所以建议使用绝对路径。
可以在 .include 文件路径之间使用等号，为了照顾旧版的 openssl，它们不支持 .include 指令，
使用 = 之后，旧版 openssl 就可以直接忽略这个不认识的选项，但如果没有等号，会报错。
> Other files can be included using the .include directive followed by a path. If the path points to a directory all files with names ending with .cnf or .conf
are included from the directory.  Recursive inclusion of directories from files in such directory is not supported. That means the files in the included
directory can also contain .include directives but only inclusion of regular files is supported there. The inclusion of directories is not supported on systems
without POSIX IO support.
>  It is strongly recommended to use absolute paths with the .include directive. Relative paths are evaluated based on the application current working directory
so unless the configuration file containing the .include directive is application specific the inclusion will not work as expected.
> There can be optional = character and whitespace characters between .include directive and the path which can be useful in cases the configuration file needs
to be loaded by old OpenSSL versions which do not support the .include syntax. They would bail out with error if the = character is not present but with it
they just ignore the include.

每个小节由若干 name=value 的键值对组成。
```ini
[ CA_default ]

dir             = ./demoCA              # Where everything is kept
certs           = $dir/certs            # Where the issued certs are kept
crl_dir         = $dir/crl              # Where the issued crl are kept
database        = $dir/index.txt        # database index file.
```
键值对中的name，允许 `[0-9a-zA-Z.,;-]`，而 value 可以包含任意字符。
name 和 value 的首尾空格会被忽略。
value 部分还允许变量替换，形式为 $var 或 ${var}，这种可以替换当前小节的变量。
要替换其它节的变量，要使用 $section::var 或者 ${section::var} 的语法。
比如，$ENV::name 可用于引用环境变量。
CONF 要求 value 部分扩展之后的长度不超过 64K，否则报错。

value 中可以用 \ 对特殊字符转义（比如$），行末使用 \ 可以续行，此外还识别
 \b \t \n \r 这些转义字符。

所有上述 value 的变量扩展和转义规则都可以在 .include 指令的文件路径中使用。

> Each section in a configuration file consists of a number of name and value pairs of the form name=value

> The name string can contain any alphanumeric characters as well as a few punctuation symbols such as . , ; and _.

> The value string consists of the string following the = character until end of line with any leading and trailing white space removed.

> The value string undergoes variable expansion. This can be done by including the form $var or ${var}: this will substitute the value of the named variable in
the current section. It is also possible to substitute a value from another section using the syntax $section::name or ${section::name}. By using the form
$ENV::name environment variables can be substituted. It is also possible to assign values to environment variables by using the name ENV::name, this will work
if the program looks up environment variables using the CONF library instead of calling getenv() directly. The value string must not exceed 64k in length after
variable expansion. Otherwise an error will occur.
> It is possible to escape certain characters by using any kind of quote or the \ character. By making the last character of a line a \ a value string can be
spread across multiple lines. In addition the sequences \n, \r, \b and \t are recognized.

> All expansion and escape rules as described above that apply to value also apply to the path of the .include directive.
### openssl 库的配置文件
基于 OpenSSL 开发的程序可以使用 OpenSSL 主配置文件或自定义配置文件自动配置
OpenSSL 的某些方面。openssl 命令行工具就是这么做到，所有 openssl 子命令默认使用
OpenSSL 主配置文件的配置，同时也可以指定别的配置文件。

> Applications can automatically configure certain aspects of OpenSSL using the master OpenSSL configuration file, or optionally an alternative configuration
file. The openssl utility includes this functionality: any sub command uses the master OpenSSL configuration file unless an option is used in the sub command
to use an alternative configuration file.

要启用库配置，必须在配置文件中的默认节中配置一行，指向主配置。
比如 openssl 命令行工具就使用 openssl_conf = xxx 指定自己的主配置节，openssl_conf
也是默认的名称，自行开发的程序可以使用自定义名称，比如 my_application_conf。

Q. enable library configuration 是什么意思?

> To enable library configuration the default section needs to contain an appropriate line which points to the main configuration section. The default name is
openssl_conf which is used by the openssl utility. Other applications may use an alternative name such as myapplication_conf.  All library configuration lines
appear in the default section at the start of the configuration file.

配置节，有一系列 name=value 对组成，name 对应要配置的模块，而 value 的含义则取决于
模块，value 可以是另一个节的名字，其中包含模块的具体配置。
> The configuration section should consist of a set of name value pairs which contain specific module configuration information. The name represents the name of
the configuration module. The meaning of the value is module specific: it may, for example, represent a further configuration section containing configuration
module specific information. E.g.:
```ini
# This must be in the default section
openssl_conf = openssl_init

[openssl_init]

oid_section = new_oids
engines = engine_section

[new_oids]

... new oids here ...

[engine_section]

... engine stuff here ...
```
> The features of each configuration module are described below.
### 注
变量展开，如果变量不存在，就会报错。比如，如果引用的环境变量不存在会导致错误。
解决方案是在默认节中提供默认值，此时如果变量未定义，就会采用默认节中的定义，当然，
这要求默认节中的定义在扩展之前出现，否则不生效。]
例如：
```ini
HOME=/temp
RANDFILE= ${ENV::HOME}/.rnd
configdir=$ENV::HOME/config
```

同一个节内多次定义同一个变量，只有最后一个生效，但有些情况（比如DNS）确实需要指定多个
值，方法是忽略name中第一个句点之前的字符。
PS：好比yaml中的数组啊。
```
1.OU="My first OU"
2.OU="My Second OU"
```
### 还有一些，不能理解，略
## .include 指令
.include 指令，被包含的文件有同名 section，会替换整个section，还是融合 section？
Ans：融合。

.include 可以理解为纯文本替换。
openssl 的配置文件，多个同名 section 会合并。
```ini
[ dn ]
C=CN
CN=chenxizhan

[ dn ]
ST=Shandong
```
等价于
```ini
[ dn ]
C=CN
CN=chenxizhan
ST=Shandong
```

# 对称加密
## demo: 对称加密
加解密、签名，或许用 gpg 更合适？

openssl提供了两种方式调用对称加密算法，openssl cipher 和 openssl enc -cipher。前者
为所有算法提供统一入口，但不能兼顾所有算法的所有选项；后者则可以兼顾完整选项。

PS：命令行接口很强大，但仍然只是部分接口，完整的功能还需要通过编程接口使用。
```bash
# 加密
echo  hello | openssl enc -aes-256-cbc -pbkdf2 -pass pass:123456 -out hello.aes
# 解密
$ openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:123456 -in hello.aes
hello
# 另外，openssl 生成的加密文件，gpg 不识别
$ gpg -d hello.aes
gpg: no valid OpenPGP data found.
gpg: decrypt_message failed: Unknown system error
```
## AES-256-CBC 对称加密

```bash
# 使用 AES 算法加密文件
# 结果文件 hello.txt.enc 是一个二进制文件
echo hello > hello.txt
openssl enc -aes256 -in hello.txt -out hello.txt.enc -pass pass:123456
# 如果不在命令行指定密码，会提示用户输入密码，交互模式下更安全

# 使用 AES 算法加密文件，并对加密结果进行 BASE64 编码
echo hello > hello.txt
openssl enc -aes256 -a -in hello.txt -out hello.txt.arm -pass pass:123456

# 解密
openssl enc -aes256 -d -in hello.txt.enc --out hello2.txt
# -e 加密，-d 解密，不指定则为加密，所以解密时不能省略 -d
```

### 警告：deprecated key derivation used
上面的加密示例在 openssl 1.1 中会得到一个警告：
```
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
```

只需要在加密的时候指定参数 -pbkdf2 就可以。

```
openssl enc -aes256 -pbkdf2 -in hello.txt -out hello.txt.enc -pass pass:123456
```
```
-iter count
    Use a given number of iterations on the password in deriving the encryption key.
    High values increase the time required to brute-force the resulting file.
    This option enables the use of PBKDF2 algorithm to derive the key.

-pbkdf2
    Use PBKDF2 algorithm with default iteration count unless otherwise specified.
```

### pbkdf2、IV 和 salt
- pbkdf2：CBC 是一种块加密模式，块加密要求密钥有相同的长度，而密码是变长的，所以要
  对密码做一些转换以便生成最终的密钥，

  pbkdf2 是一种安全的密钥生成算法。

- IV，Initialization Vector

  CBC 模式下，每个块在加密之前要先和前一个块进行异或计算，第一个块没有前一个块，
  所以提供 IV 作为初始块。

- salt：为了提高安全性，相同的密码应当生成不同的密钥，这需要引入干扰项，就是盐。

AES加密算法的CBC模式加密时实际使用密钥和IV，算法没有规定 key 和 iv 如何生成和存储。

openssl 的 AES + CBC 加密，默认通过 passwd 和 salt 生成 key 和 iv，生成过程用到
哈希算法。也可以不指定passwd，而是直接指定 key 和 iv。

openssl aes-256-cbc 加密时，要么通过 -K key 和 -iv IV 直接指定 key 和 iv。
要么通过 -pass 指定密码，然后 openssl 随机生成 salt，并使用默认哈希算法。

- 用 -p 或者 -P 能查看实际使用的 key 和 iv，用于调试。
- 通过 -S 显式指定 salt，还可以通过 -nosalt 禁用盐。当然-S 和 -nosalt 都不够安全。
- 通过 -md 显式指定哈希算法。
  openssl 1.0 默认使用 md5 做哈希算法，1.1 开始使用 sha256作为默认哈希，
  通过 /etc/ssl/openssl.cnf 的 default_md 字段修改默认的 hash 函数。

  ps：当然，解密使用的哈希算法要和加密时的哈希算法一致。

```
-p  Print out the key and IV used.
-P  Print out the key and IV used then immediately exit: don't do any encryption or decryption.
```

AES 算法 Key 和 IV 的生成规律：将 hash 结果（第一次 hash 运算时为空）、passphrase 和 salt（nosalt 时为空）拼接后
循环做 hash 运算，再根据 AES 所需的 Key 和 IV 的 bit 数取值。

对于 AES-256-CBC 来说，MD5
```
hash1_128 = MD5(Passphrase + Salt)
hash2_128 = MD5(hash1_128 + Passphrase + Salt)
hash3_128 = MD5(hash2_128 + Passphrase + Salt)
Key = hash1_128 + hash2_128
IV  = hash3_128
```

更进一步的，只要生成了足够 bit 位的值，hash 运算就停止了，这称为一个迭代，这正是 OpenSSL 为人所诟病的不足。
所以 openssl 1.1 引入了 -iter 和 -pbkdf2 参数。

AES/ECB/PKCS5Padding

块模式下，一般使用 PKCS#5 补齐。
> All the block ciphers normally use PKCS#5 padding, also known as standard block padding.
This allows a rudimentary integrity or password check to be performed. However, since the
chance of random data passing the test is better than 1 in 256 it isn't a very good test.

[OpenSSL AES 算法中 Key 和 IV 是如何生成的](https://blog.lancitou.net/how-to-generate-key-and-iv-in-openssl-aes/)
[appsec - How to securely hash passwords?](https://security.stackexchange.com/questions/211/how-to-securely-hash-passwords/31846#31846)
[encryption - Why would you need a salt for AES-CBS when IV is already randomly generated and stored with the encrypted data?](https://security.stackexchange.com/questions/48000/why-would-you-need-a-salt-for-aes-cbs-when-iv-is-already-randomly-generated-and)

### Q. aes 加密的时候会加入随机的盐，那解密的时候如何得知盐值？
openssl 将盐保存在加密文件的开头。验证如下：

```bash
# 加密，使用 -p 输出盐
$ openssl enc -aes-256-cbc -in hello.txt -out hello.txt.enc -pass pass:123456 -pbkdf2 -p
salt=0AC8FA8EAFB9ECD7
key=1BF6A315A41C0F9DA720CD4FEC7552F01C83B60C72A227D1B7D5F6EA13CE107D
iv =B125FFC70231378EE7F17EEAC7AC6D08
# xxd 命令查看，能看到第10到16个字节就是盐
$ xxd hello.txt.enc
00000000: 5361 6c74 6564 5f5f 0ac8 fa8e afb9 ecd7  Salted__........
00000010: 9864 97b6 b02e ba6f ef92 e511 4967 d3f5  .d.....o....Ig..
```
### Q. pkbdf2 迭代多少次好呢？
``足够好''是主观的且难以定义的，因应用程序和风险状况而异，今天的``足够好''明天可能不会``足够好''...

一些参考资料：
- 2000年9月-建议进行1000余轮（来源：RFC 2898）
- 2005年2月-Kerberos 5中的AES``默认''为4096轮SHA-1。 （来源：RFC 3962）
- 2010年9月-ElcomSoft声称iOS 3.x使用2,000次迭代，iOS 4.x使用10,000次迭代，显示BlackBerry使用1次（未声明确切的哈希算法）（来源： ElcomSoft ）
- 2011年5月-LastPass使用100,000次SHA-256迭代（来源： LastPass ）
- 2015年6月-StableBit使用了200,000次SHA-512迭代（来源： StableBit CloudDrive螺母和螺栓 ）
- 2015年8月-CloudBerry使用SHA-1的1,000次迭代（来源： CloudBerry实验室安全注意事项（pdf） ）

[cryptography — 使用PKBDF2-SHA256时建议的迭代次数？](https://www.it-swarm.cn/zh/cryptography/使用pkbdf2sha256时建议的迭代次数？/l957335351/)
### Q. pbkdf2 的默认迭代次数是多少？ 10000 次
```bash
# 加密
$ openssl enc -aes-256-cbc -in hello.txt -out hello.txt.enc -pass pass:123456 -pbkdf

# 解密，
$ openssl enc -aes-256-cbc -d -in hello.txt.enc  -pass pass:123456 -pbkdf2
hello
```

加密解密的迭代次数必须相同。
```
$ openssl enc -aes-256-cbc -in hello.txt -out hello.txt.enc -pass pass:123456 -iter 1000 -p

$ openssl enc -aes-256-cbc -d -in hello.txt.enc  -pass pass:123456 -iter 1001
bad decrypt
140607393125696:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:../crypto/evp/evp_enc.c:583:

$ openssl enc -aes-256-cbc -d -in hello.txt.enc  -pass pass:123456 -pbkdf2
bad decrypt
140513093121344:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:../crypto/evp/evp_enc.c:583:
```
#### 暴力确认默认迭代次数

```bash
$ echo hello > hello.txt
$ openssl enc -aes-256-cbc -in hello.txt -out hello.txt.enc -pass pass:123456 -pbkdf2 -p
salt=0AC8FA8EAFB9ECD7
key=1BF6A315A41C0F9DA720CD4FEC7552F01C83B60C72A227D1B7D5F6EA13CE107D
iv =B125FFC70231378EE7F17EEAC7AC6D08
$ time for ((i = 1; i<= 10000; i++)); do
    if openssl enc -aes-256-cbc -d -in hello.txt.enc  -pass pass:123456 -iter $i &>/dev/null;then
      result=$(openssl enc -aes-256-cbc -d -in hello.txt.enc  -pass pass:123456 -iter $i)
      echo "i = $i", $result
      if [ "$result" == "hello" ]; then break; fi
    fi
    if ((i % 100 == 0)); then
      echo $i
    fi
done
```

1. 解密失败，退出码为1；解密成功，退出码为0
2. 根据资料，常见迭代次数 10000 以内，有理由认为 openssl 的次数不会超过它，所以暴力尝试是可行的

运行了 1.5 分钟。
## 实战：openssl 解密java的AES/ECB/PKCS5Padding加密结果
2021-11-02

山东重工集团财务有限公司，现场开发，对接云之家审批流，其回调数据是通过 Java 加密的。
现在要用 openssl 解密数据。

要解密的数据存放在文件 demo.json.enc.base64 中。

解密命令为
```bash

$ xxd -g 32 <<< T22cdkEko3flglPe
00000000: 4e4d65324a4151536e796a474d716666  NMe2JAQSnyjGMqff
00000010: 0a

$ openssl enc -aes-128-ecb -d -K 4e4d65324a4151536e796a474d716666 -in demo.json.enc.base64 -out demo.json  -base64 -A
```

根据
```java
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
String key = "T22cdkEko3flglPe";
```
得知这里使用的 AES/ECB/PKCS5Padding 加密，密钥长度 128 位，另外根据资料，使用 sha1 哈希。

1. openssl 默认使用密码生成 key，而 Java 使用 T22cdkEko3flglPe 二进制形式直接作为 key，
  所以用 xxd 取得对应的16进制形式。
2. 密钥长度为 32 个字符，对应 128 位，所以确定为 -aes-128-ecb
3. openssl 默认使用 PKCS#5 方式填充，所以无需指定
4. -d 表示解密
5. -base64 表示先对输入文件进行 base64 解码
6. -A 告诉openssl，base64 内容没有换行。如果不指定这个，openssl 只能解密部分数据。
7. ecb 模式不需要初始向量（iv），所以不需要指定 -iv 选项。

### 附：要解密的数据
```
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
```
### 附：Java 的加密、解密相关代码段
```java
package com.soflyit.data.governance.web.platform.flow.service;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;

// 128位长度的AES加密
public class AESEncryptor {
    private static final Charset CHARSET = StandardCharsets.UTF_8;
    private static final String ALGORITHM = "AES";

    private String aesKey;

    public AESEncryptor(String aesKey) {
        this.aesKey = aesKey;
    }

    public String encrypt(String data) {
        byte[] ciperData = encrypt(data.getBytes(CHARSET));
        return Base64.encodeBase64String(ciperData);
    }

    public byte[] encrypt(byte[] data) {
        Key k = new SecretKeySpec(aesKey.getBytes(CHARSET), ALGORITHM);
        byte[] raw = k.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(raw, ALGORITHM);
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decrypt(String data) {
        byte[] plainData = decrypt(Base64.decodeBase64(data));
        return new String(plainData, CHARSET);
    }

    public byte[] decrypt(byte[] data) {
        Key k = new SecretKeySpec(aesKey.getBytes(CHARSET), ALGORITHM);
        byte[] raw = k.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(raw, ALGORITHM);
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String key = "NMe2JAQSnyjGMqff";

        // 解密推送数据
        // 其中cipher为接收到的原始推送数据
        //  很长很长，此处省略
        String cipher = "";
        AESEncryptor encryptor = new AESEncryptor(key);
        encryptor.decrypt(cipher);
    }
}

```

# 非对称加密
rsa 和 ec 这两个。

对于 rsa，有 genrsa、rsa 和 rsautl
对于 ec，有 ecparam 和 ec 两个命令。

同时还提供了统一管理的命令，genpkey、pkey、pkparam、pkutl。

genrsa 命令生成rsa密钥，rsa 和 rsautl 不能生成。
rsa 命令管理密钥，查看、校验、格式转换。
rsautl 命令使用rsa密钥，即用密钥加密、解密、签名、校验签名。

ecparam 生成和查看 ec 密钥参数，生成 ec 密钥；
ec 用于查看ec密钥。
没有 ecutl 命令。

genpkey 用于生成公钥参数（EC，DH等），用于生成公钥（RSA，DSA,EC）。
pkeyparam 用于查看公钥参数。
pkey 管理公钥。
pkutl 使用公钥。

## demo: 生成和查看rsa密钥
```bash
# 创建新密钥
# 默认密钥长度为 2048 位，最后的 512 指定生成 512 位的密钥
# 默认在标准输出显示密钥，-out 指定保存到文件 key.pem
openssl genrsa -out key.pem 512
openssl genrsa 512 > key.pem
# 或者
openssl genrsa > key.pem

# 查看密钥信息
# 默认从标准输入读取密钥，-in 指定从文件读取
openssl rsa -in key.pem -noout -text
cat key.pem | openssl rsa -noout -text

# 除了 -text 查看完整的密钥信息，也可以使用其它选项查看单独的一部分
# 比如公钥
openssl rsa -pubout < key.pem
openssl rsa -pubout < key.pem > pub.pem

```

也可以使用 genpk 命令生成 rsa 密钥
```bash
openssl genpkey -algorithm rsa -out rsa.pem
openssl genpkey -algorithm rsa -pkopt rsa_keygen_bits:512 -out rsa.pem
```

具体的输出过程如下：
```sh

# 创建新密钥，512位（默认2048位）
$ openssl genrsa -out key.pem 512
Generating RSA private key, 512 bit long modulus (2 primes)
...........+++++++++++++++++++++++++++
............+++++++++++++++++++++++++++
e is 65537 (0x010001)

# 只有一个文件（私钥文件）
$ ls
key.pem

# 私钥内容
$ cat key.pem
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAJWaPgx6yiLUE+GlDQuC6+U+gLYJtFlsfUJYz/8/AGabmF/ZDE8K
Q4oPtaJrg/5pVZMzoB7uoTfuzm/jeE3BRJUCAwEAAQJAa578SCoFRCzg6JC946wZ
W18tZMdycGo1agdOCkceWLE4wQBCoayUIK4/z8SaOXfXquQjA047mwRUDgD1ZgUE
wQIhAManFM4+ZlPHstoIiwggQQwZNgskSf7iHUUxdMuEBbrpAiEAwMo8D796WCM4
T8eufvDWBGogFZW3J/hb1LUXvq4G2M0CIEmBZYdzO3XgvONEqf1VwfvyEDdLND4l
+OKzjB4KOfyRAiAKZJyaSLtCtxtZCa25gCg5crMqFrkZ+YSR0fVmvSD3XQIhAK51
PJkOxGFOXW6OgCged7jRNAJ8gQJRS094sTKR44Om
-----END RSA PRIVATE KEY-----
# 查看密钥组件（可以看到，里面包含了公钥）
$ openssl rsa -in key.pem -text
RSA Private-Key: (512 bit, 2 primes)
modulus:
    00:95:9a:3e:0c:7a:ca:22:d4:13:e1:a5:0d:0b:82:
    eb:e5:3e:80:b6:09:b4:59:6c:7d:42:58:cf:ff:3f:
    00:66:9b:98:5f:d9:0c:4f:0a:43:8a:0f:b5:a2:6b:
    83:fe:69:55:93:33:a0:1e:ee:a1:37:ee:ce:6f:e3:
    78:4d:c1:44:95
publicExponent: 65537 (0x10001)
privateExponent:
    6b:9e:fc:48:2a:05:44:2c:e0:e8:90:bd:e3:ac:19:
    5b:5f:2d:64:c7:72:70:6a:35:6a:07:4e:0a:47:1e:
    58:b1:38:c1:00:42:a1:ac:94:20:ae:3f:cf:c4:9a:
    39:77:d7:aa:e4:23:03:4e:3b:9b:04:54:0e:00:f5:
    66:05:04:c1
prime1:
    00:c6:a7:14:ce:3e:66:53:c7:b2:da:08:8b:08:20:
    41:0c:19:36:0b:24:49:fe:e2:1d:45:31:74:cb:84:
    05:ba:e9
prime2:
    00:c0:ca:3c:0f:bf:7a:58:23:38:4f:c7:ae:7e:f0:
    d6:04:6a:20:15:95:b7:27:f8:5b:d4:b5:17:be:ae:
    06:d8:cd
exponent1:
    49:81:65:87:73:3b:75:e0:bc:e3:44:a9:fd:55:c1:
    fb:f2:10:37:4b:34:3e:25:f8:e2:b3:8c:1e:0a:39:
    fc:91
exponent2:
    0a:64:9c:9a:48:bb:42:b7:1b:59:09:ad:b9:80:28:
    39:72:b3:2a:16:b9:19:f9:84:91:d1:f5:66:bd:20:
    f7:5d
coefficient:
    00:ae:75:3c:99:0e:c4:61:4e:5d:6e:8e:80:28:1e:
    77:b8:d1:34:02:7c:81:02:51:4b:4f:78:b1:32:91:
    e3:83:a6
writing RSA key
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAJWaPgx6yiLUE+GlDQuC6+U+gLYJtFlsfUJYz/8/AGabmF/ZDE8K
Q4oPtaJrg/5pVZMzoB7uoTfuzm/jeE3BRJUCAwEAAQJAa578SCoFRCzg6JC946wZ
W18tZMdycGo1agdOCkceWLE4wQBCoayUIK4/z8SaOXfXquQjA047mwRUDgD1ZgUE
wQIhAManFM4+ZlPHstoIiwggQQwZNgskSf7iHUUxdMuEBbrpAiEAwMo8D796WCM4
T8eufvDWBGogFZW3J/hb1LUXvq4G2M0CIEmBZYdzO3XgvONEqf1VwfvyEDdLND4l
+OKzjB4KOfyRAiAKZJyaSLtCtxtZCa25gCg5crMqFrkZ+YSR0fVmvSD3XQIhAK51
PJkOxGFOXW6OgCged7jRNAJ8gQJRS094sTKR44Om
-----END RSA PRIVATE KEY-----
# 把公钥单独提取出来
$ openssl rsa -in key.pem -out pub.pem -pubout
writing RSA key
$ cat pub.pem
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJWaPgx6yiLUE+GlDQuC6+U+gLYJtFls
fUJYz/8/AGabmF/ZDE8KQ4oPtaJrg/5pVZMzoB7uoTfuzm/jeE3BRJUCAwEAAQ==
-----END PUBLIC KEY-----
# 检查密钥文件的一致性
$ openssl rsa -in key.pem  --check
RSA key ok
……

```
上面的示例都在使用 -in 和 -out 指定输入输出，其实也可以使用重定向
```bash

$ openssl genrsa 512 > rsa.pem
Generating RSA private key, 512 bit long modulus (2 primes)
..+++++++++++++++++++++++++++
.................+++++++++++++++++++++++++++
e is 65537 (0x010001)

$ cat rsa.pem
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAL67EmxXiu2pFQDZtgMc9zePAOHB+P6PwS8ZhdmIFvLbfu36b/jj
a9HDKgcLo5hCyd/nkaSYZ3elkghjX8BckYsCAwEAAQJAHbs7m/fpiDKbO460eLfD
Mb3w/UAneEcgbh8kZkx4h1K7BW06/+fQXvfgE6z/EKJJETzKcaROMxEt5zqCjWfS
gQIhAOJWDRBtJ6rPhUo7BUku2Y5M03WmiLmW7/HkV89DCHCJAiEA17pm2Obgbti8
/vs1ZRiWfwtqBMb2n9xQkH5yXF6Y5HMCIQCYilhJrtdiJnR1v+tjFEEpx5tomnFh
a1mRlEyd8laYyQIgVldejnVpYjQRAKSebEX5BgQVfK/9SWIuRIa3UszxuI0CIE1m
x5yhLZWshvJ9lyaW5jQNcMGAsNFJDvv7VEej90yJ
-----END RSA PRIVATE KEY-----

$ openssl rsa -pubout < rsa.pem
writing RSA key
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL67EmxXiu2pFQDZtgMc9zePAOHB+P6P
wS8ZhdmIFvLbfu36b/jja9HDKgcLo5hCyd/nkaSYZ3elkghjX8BckYsCAwEAAQ==
-----END PUBLIC KEY-----

$ openssl rsa -pubout < rsa.pem  > rsa-pub.pem
writing RSA key

$ openssl rsa -pubin < rsa-pub.pem --check
Only private keys can be checked

$ openssl rsa -pubin < rsa-pub.pem
writing RSA key
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL67EmxXiu2pFQDZtgMc9zePAOHB+P6P
wS8ZhdmIFvLbfu36b/jja9HDKgcLo5hCyd/nkaSYZ3elkghjX8BckYsCAwEAAQ==
-----END PUBLIC KEY-----
```
## demo: 生成 ecc 密钥

man ecparam
man ec
```sh
# 创建ec参数。To create EC parameters with the group 'prime192v1':
openssl ecparam -out ec_param.pem -name prime192v1
# 列出所有可用的曲线名字，
openssl ecparam -list_curves
# brainpoolP512r1, secp521r1, prime256v1

# 校验参数文件：To validate given EC parameters:
openssl ecparam -in ec_param.pem -check

# 用指定的参数文件创建密钥对
openssl ecparam -in ec_param.pem -genkey

# 创建参数的同时创建私钥文件。To create EC parameters and a private key:
openssl ecparam -out ec_key.pem -name prime192v1 -genkey

# 把参数输出到标准输出。To print out the EC parameters to standard output:
openssl ecparam -in ec_param.pem -noout -text
# ps：-text 表示以人类可读的形式输出。 -noout 则表示抑制输出编码后的参数

##########################
# 用 3DES 加密私钥文件.
openssl ec -in key.pem -des3 -out keyout.pem
#  ps: openssl ecn -ciphers 可以查看所有可用的加密算法

# 从pem格式转为der格式
openssl ec -in key.pem -ouform der -out keyout.der

# 查看 ECC 密钥文件的公钥、私钥组件，以及密钥参数。
openssl ec -in key.pem -text
openssl ec -in key.pem -text -noout # -noout 指定抑制输出编码后的格式
# 导出其中的公钥
openssl ec -in key.pem  -pubout -out pubkey.pem
```
## genrsa
关于密钥的密码保护

genrsa 有个 -passout 选项，可以直接指定密码，还有 -* 允许指定任意支持的加密算法。
仅指定 -passout 没有用。
仅指定 -* （比如 -aes256），会提示输入密码。也可以同时指定二者。
```bash
openssl genrsa -passout pass:123456 -aes256 > rsa.pem
```
不加密的，是这样
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwRVXUpXi4sC/tOtfZQrPoPJoeYuByaoYkQNH4gZnORN8B0N5
……
-----END RSA PRIVATE KEY-----
```
设置密码保护之后，会多两行相关信息。
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,3D97EFFFE7B5B40955AEC145C9BB1983

r5ScBEcXaWsLth2ql7f/yIFRr22z/Fg/I3rA1QkT1oaq4dIqVOSeksbxTqzQ5ncl
1VjNgTsCMePAqhLs/gGE/DNAngXIE82U7/qop+4POdqC4VRRfDVzABuUz1R1lCmy
```
## rsautl
此命令用 RSA 算法加密、解密、签名、验证签名。
此命令直接使用 rsa 算法，所以只能操作小量的数据。

准备密钥和文件
```bash
PASSWORD=123456
$ openssl genrsa -aes256 -passout pass:$PASSWORD > rsa.pem
Generating RSA private key, 2048 bit long modulus (2 primes)
..................+++++
.................................................................................................+++++
e is 65537 (0x010001)

$ openssl rsa -pubout -passin pass:$PASSWORD < rsa.pem > pub.pem
writing RSA key

$ echo hello > hello.txt
```
```bash
# 公钥加密
openssl rsautl -encrypt -in hello.txt -inkey  rsa.pem -passin pass:$PASSWORD -out enc
# 注：私钥文件本身包含公钥，加密的时候也可以直接指定私钥文件，openssl 自动提取其中的公钥进行加密。
openssl rsautl -encrypt -in hello.txt -inkey  pub.pem -pubin -out enc
# 另外，同样的文件，分别加密，得到的加密文件不一样
# 私钥解密
$ openssl rsautl -decrypt -in enc -inkey rsa.pem -passin pass:$PASSWORD
hello

# 私钥签名
openssl rsautl -sign -in hello.txt -inkey rsa.pem -passin pass:$PASSWORD -out sign
# 同样的文件，分别签名，得到的结果是一样的。
# 公钥验证
$ openssl rsautl -verify -in sign -inkey pub.pem -pubin
hello
# Q. 签名文件，竟然包含原始数据，感觉不大对劲啊？
```

用私钥随便给一点数据签名
```bash
openssl rsautl -sign -in file -inkey key.pem -out sig
```
恢复签名的数据
```bash
openssl rsautl -verify -in sig -inkey key.pem
```
查看签名数据的原始格式
```bash
openssl rsautl -verify -in sig -inkey key.pem -raw -hexdump
```
```
0000 - 00 01 ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
0010 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
0020 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
0030 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
0040 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
0050 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
0060 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
0070 - ff ff ff ff 00 68 65 6c-6c 6f 20 77 6f 72 6c 64   .....hello world
```
很明显符合 PKCS#1 的数据格式。如果这数据是使用 encrypt/decrypt 命令生成的，数据块
格式会是 type2 (第二个字节位 0x02)，且中间填充的是随机字节而非 0xff。

```bash
$ openssl rsautl -sign -in file2 -inkey id.pem -out enc2
RSA operation error
139705553990976:error:0406C06E:rsa routines:RSA_padding_add_PKCS1_type_1:data too large for key size:../crypto/rsa/rsa_pk1.c:25:
```

# openssl s_client
2021-11-03

命令的用途。
> The s_client command implements a generic SSL/TLS client which connects to a
remote host using SSL/TLS. It is a very useful diagnostic tool for SSL servers.

## demo：访问远程 HTTPS 服务器并返回结果
最基础的功能，充当与 TLS 服务端通信的交互式客户端。用 -connect 命令访问服务器。
```bash
openssl s_client -connect httpbin.org:443
# 或者省略 -connect
openssl s_client httpbin.org:443
```
会有如下输出，可以看到，openssl s_client 详细列出了证书层级，并打印了服务端证书。
```
CONNECTED(00000003)
depth=2 C = US, O = Amazon, CN = Amazon Root CA 1
verify return:1
depth=1 C = US, O = Amazon, OU = Server CA 1B, CN = Amazon
verify return:1
depth=0 CN = httpbin.org
verify return:1
---
Certificate chain
 0 s:CN = httpbin.org
   i:C = US, O = Amazon, OU = Server CA 1B, CN = Amazon
 1 s:C = US, O = Amazon, OU = Server CA 1B, CN = Amazon
   i:C = US, O = Amazon, CN = Amazon Root CA 1
 2 s:C = US, O = Amazon, CN = Amazon Root CA 1
   i:C = US, ST = Arizona, L = Scottsdale, O = "Starfield Technologies, Inc.", CN = Starfield Services Root Certificate Authority - G2
 3 s:C = US, ST = Arizona, L = Scottsdale, O = "Starfield Technologies, Inc.", CN = Starfield Services Root Certificate Authority - G2
   i:C = US, O = "Starfield Technologies, Inc.", OU = Starfield Class 2 Certification Authority
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIFbzCCBFegAwIBAgIQAzSkeUH+rIUZVH0Oqpvw5jANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0yMDEyMjEwMDAwMDBaFw0yMjAxMTky
MzU5NTlaMBYxFDASBgNVBAMTC2h0dHBiaW4ub3JnMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAsR1fF+JAA+s/O8YGXONxK5JRc+4z/NtiFAww39lC/2qW
D2b/30ojrJVNbE500QzOTOO0YoJ3eWJupjIqFm3ImK+x8gSCWNz+pneWVY7RaoEb
mSgZRQ9YizYpVUnS4wb5UxhkzvCwsaEhqWja6yP0inaUIuW3gzrTuKTG2VBAnMtc
xYn7ttes9/BZebh0giSO0vtj7pg8Ai0n3I2moNHUumiJ1ye3pYEjys32sSb0HUGJ
f+T0k5ELs+dBM/Z7SuCq9toLNX/Uj196ZPQiv+BhCmM4VQyID5wR5riIR11/0z0E
r4FZjLAPNBFlE5bOMC87UXSf7kylvgZUuLHOKOFc2wIDAQABo4IChzCCAoMwHwYD
VR0jBBgwFoAUWaRmBlKge5WSPKOUByeWdFv5PdAwHQYDVR0OBBYEFHZOjrUHdkbF
RaBO20nVbqaNuinoMCUGA1UdEQQeMByCC2h0dHBiaW4ub3Jngg0qLmh0dHBiaW4u
b3JnMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
AwIwOwYDVR0fBDQwMjAwoC6gLIYqaHR0cDovL2NybC5zY2ExYi5hbWF6b250cnVz
dC5jb20vc2NhMWIuY3JsMCAGA1UdIAQZMBcwCwYJYIZIAYb9bAECMAgGBmeBDAEC
ATB1BggrBgEFBQcBAQRpMGcwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLnNjYTFi
LmFtYXpvbnRydXN0LmNvbTA2BggrBgEFBQcwAoYqaHR0cDovL2NydC5zY2ExYi5h
bWF6b250cnVzdC5jb20vc2NhMWIuY3J0MAwGA1UdEwEB/wQCMAAwggEFBgorBgEE
AdZ5AgQCBIH2BIHzAPEAdwApeb7wnjk5IfBWc59jpXflvld9nGAK+PlNXSZcJV3H
hAAAAXaC8EAVAAAEAwBIMEYCIQDNxxAPWT/gy6wFsupHR/4vfmLTtpxkCZt8FhqE
+quq9gIhAPXuElDhqg376uQXhF9W6q2TluHS/Xs4f1hB5sNwA9XNAHYAQcjKsd8i
RkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvYAAAF2gvBAHgAABAMARzBFAiB1FlMU
CTCW/tGD8Pskp1jxeelWhd4/uJMhsuBjXs81dQIhANcn0p9bbEkyVjPopr3xBh1H
VxY7nZNecoqRzeE2e0elMA0GCSqGSIb3DQEBCwUAA4IBAQAnnWtk2DykzfJ+Xs2q
tYFutai46RkGb0rwXgeWNXzYl7MFu44gXCR5n3ctrrz83YlPJM7fBHsI1NR39XeD
yn1XiZeVuF3JGse2/gDuYf7aUKJoEXMpZclF8MLUAMKZS4zj6WwJdhYuIDHr8quP
7AkunuP8fZ8qyApDiDNAklENqsz40C26Nest8oSYSAbcXBD3RLtBLQot5O6XI88f
qKx1DjJaaDsFNdXT8O5NRX85Sy8XrgIt6fgi25Sw4HXepZmsmXDIAUyQnnCCLkiy
UAHjRHcbR6pWDmxjoMCPkVpPEPxPXfXjsZXELPbKewwW57x3xsmUidnR/WowI0ru
s+Zn
-----END CERTIFICATE-----
subject=CN = httpbin.org

issuer=C = US, O = Amazon, OU = Server CA 1B, CN = Amazon

---
No client certificate CA names sent
Peer signing digest: SHA512
Peer signature type: RSA
Server Temp Key: ECDH, P-256, 256 bits
---
SSL handshake has read 5510 bytes and written 429 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256
    Session-ID: BD223B59767C7266F2636E06247F5DF1DBA5E291493A8D74D5020E15AE9E67B4
    Session-ID-ctx:
    Master-Key: 5E49A933CD2031579ACA4A7A11FCD60C2FBFBF90017BB5E946FE64BD93308D0B959FE68D911E16B634EB2509A675FA73
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 43200 (seconds)
    TLS session ticket:
    0000 - 01 62 3f 4b 7b 86 d6 06-2b f6 26 53 5c 90 ad a5   .b?K{...+.&S\...
    0010 - 1c 18 f7 2a 4d e7 5a cb-0d 14 48 b8 b7 c3 8c a1   ...*M.Z...H.....
    0020 - ef e6 ed ad e7 6b 1d 03-d5 5f 83 06 6d 2f e8 87   .....k..._..m/..
    0030 - 5b a7 ac 50 a3 fd ab 2b-52 bb f9 c2 fd d1 48 16   [..P...+R.....H.
    0040 - 10 50 2b cf 19 d8 fa fb-a9 2d d9 b8 aa da 4a 86   .P+......-....J.
    0050 - 6a 79 97 bc e9 7a ab d8-e4 bb f9 92 62 0e 4a bc   jy...z......b.J.
    0060 - d3 a1 19 ac a8 59 c2 36-fa a1 09 53 8d f7 0c d0   .....Y.6...S....
    0070 - 8b 6e e1 bf 69 36 df 40-47 52 e5 f7 1d 49 be ca   .n..i6.@GR...I..
    0080 - 51 ca ec 94 31 02 c4 c2-01 23 1f 3a 05 47 f4 f6   Q...1....#.:.G..
    0090 - 81 1f 03 26 bb 34 41 01-01 51 6d 81 7b fb ea 11   ...&.4A..Qm.{...
    00a0 - 3d f3 1b 8f 95 3d a5 bf-09 0d 7f 35 e5 c1 b8 3a   =....=.....5...:
    00b0 - 5e bd b7 f5 14 7a e9 84-2e 29 ee 27 57 60 c4 dd   ^....z...).'W`..

    Start Time: 1635909678
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
---
```

此时暂停，等待输入，接着输入如下三行内容（第三行是空行），发送HTTP请求
```
GET /get HTTP/1.1
HOST: httpbin.org

```
服务端返回消息。
```bash
HTTP/1.1 200 OK
Date: Wed, 03 Nov 2021 03:21:32 GMT
Content-Type: application/json
Content-Length: 200
Connection: keep-alive
Server: gunicorn/19.9.0
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

{
  "args": {},
  "headers": {
    "Host": "httpbin.org",
    "X-Amzn-Trace-Id": "Root=1-6182003c-2b940ef652d7835242737a14"
  },
  "origin": "124.133.27.115",
  "url": "https://httpbin.org/get"
}
```
暂停，等待输入，接着输入Ctrl-D模拟EOF，结束通信。然后命令输出 DONE。
```bash
DONE
```
### 附：不要加协议前缀，识别不了
```bash
$ openssl s_client https://httpbin.org
139724921500992:error:2008F002:BIO routines:BIO_lookup_ex:system lib:../crypto/bio/b_addr.c:730:Servname not supported for ai_socktype
connect:errno=0
```
### 附：访问远程 HTTP 不会有结果
```bash
openssl s_client -connect httpbin.org:80
```
自动就结束了
```
CONNECTED(00000003)
140059842250048:error:1408F10B:SSL routines:ssl3_get_record:wrong version number:../ssl/record/ssl3_record.c:331:
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 5 bytes and written 303 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
```
## demo: 提取服务端 SSL/TLS 证书
```bash
# 把服务器证书保存到文件中
openssl s_client -connect httpbin.org:443 </dev/null | openssl x509 -out httpbin.org.crt
# 直接解析证书字段
openssl s_client -connect httpbin.org:443 </dev/null | openssl x509 -noout -text
```

```bash
# 获取根证书
openssl s_client -connect httpbin.org:443 -showcerts </dev/null | openssl x509 -out root.crt
# 或者
openssl s_client -connect httpbin.org:443 -showcerts </dev/null 2>/dev/null | openssl x509 -out root.crt
```
## 实例：-brief 和 -quiet
s_client默认会输出证书和会话信息，如果希望简洁一些，可以指定 -brief 选项。
```bash
$ openssl s_client -connect letsencrypt.org:443 -brief
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = lencr.org
Hash used: SHA256
Signature type: ECDSA
Verification: OK
Server Temp Key: X25519, 253 bits
```
另外，-quiet 更简洁，但我发先会导致验证失败，不知何故。
```bash
$ openssl s_client -connect letsencrypt.org:443 -quiet
depth=2 C = US, O = Internet Security Research Group, CN = ISRG Root X1
verify return:1
depth=1 C = US, O = Let's Encrypt, CN = R3
verify return:1
depth=0 CN = lencr.org
verify return:1
```
# openssl s_server

openssl s_server 监听 8443 端口，使用 server.pem 证书，

- 服务端证书
  - `-cert infile` 默认 server.pem。
  - 需要提供服务端证书的私钥文件 -key infile，默认使用证书
  - 不使用证书 -nocert
    > If this option is set then no certificate is used. This restricts the
    cipher suites available to the anonymous ones (currently just anonymous DH).

- 验证客户端证书
  - 默认不验证客户端证书，指定 -verify int, -Verify int 验证客户都安证书
    -verify 选项开启验证，但客户端可以不提供证书，-Verify开启验证，且客户端必须提供证书。
  - `-CAfile infile`    验证客户端时使用的证书
  - `-no-CAfile`

- 详细级别
  - `-quiet`  Inhibit printing of session and certificate information.
  - `-brief`  Provide a brief summary of connection parameters instead of the normal verbose output.
- 模拟 HTTP
  - `-HTTP`  Emulates a simple web server. Pages will be resolved relative to the current directory.
    The files loaded are assumed to contain a complete and correct HTTP response (lines that are part of the HTTP response
    line and headers must end with CRLF).

## demo: s_server 和 s_client 发送消息
先启动服务端，默认监听 4433 端口，启动时要指定服务器证书和私钥文件路径
```bash
# server
openssl s_server -cert pem/server-cert.pem -key pem/server-key.pem  -brief
```
另开一个端口，作为客户端去连接服务器端，默认连接 localhost:4433
```bash
$ openssl s_client -brief
depth=0 CN = localhost
verify error:num=20:unable to get local issuer certificate
depth=0 CN = localhost
verify error:num=21:unable to verify the first certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = localhost
Hash used: SHA256
Signature type: RSA-PSS
Verification error: unable to verify the first certificate
Server Temp Key: X25519, 253 bits
# 等待
```
同时，服务端会打印 TLS 会话信息，如下：
```bash
# server
Protocol version: TLSv1.3
Client cipher list: TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:TLS_EMPTY_RENEGOTIATION_INFO_SCSV
Ciphersuite: TLS_AES_256_GCM_SHA384
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
No peer certificate
Supported Elliptic Groups: X25519:P-256:X448:P-521:P-384
```
然后在客户端输入消息，换行
```bash
hello
```
服务端就会看到消息
```bash
$ openssl s_server -cert pem/server-cert.pem -key pem/server-key.pem  -brief
Protocol version: TLSv1.3
# ...
Supported Elliptic Groups: X25519:P-256:X448:P-521:P-384
hello
```
同样，服务器端也可以给客户端发消息
```bash
message from server
```

这是完整的客户端输出
```bash
$ openssl s_client -brief
depth=0 CN = localhost
verify error:num=20:unable to get local issuer certificate
depth=0 CN = localhost
verify error:num=21:unable to verify the first certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = localhost
Hash used: SHA256
Signature type: RSA-PSS
Verification error: unable to verify the first certificate
Server Temp Key: X25519, 253 bits
hello
message from server
CONNECTION CLOSED BY SERVER
```

这是完整的服务端
```bash
$ openssl s_server -cert pem/server-cert.pem -key pem/server-key.pem  -brief
Protocol version: TLSv1.3
Client cipher list: TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:TLS_EMPTY_RENEGOTIATION_INFO_SCSV
Ciphersuite: TLS_AES_256_GCM_SHA384
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
No peer certificate
Supported Elliptic Groups: X25519:P-256:X448:P-521:P-384
hello
message from server
^C
```

另外，启动客户端时还可以指定 CA 文件，这样就能成功验证服务器证书了。
```bash
$ openssl s_client -brief -CAfile pem/ca.pem
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = localhost
Hash used: SHA256
Signature type: RSA-PSS
Verification: OK
Server Temp Key: X25519, 253 bits
```
## demo: s_server 做简单的HTTP服务器
```bash
cat <<EOF > foo.txt
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 7

success
EOF

$ openssl s_server -cert pem/server-cert.pem -key pem/server-key.pem    -HTTP
Using default temp DH parameters
ACCEPT
FILE:foo.txt
FILE:foo.txt

```
```bash
$ curl -k https://localhost:4433/foo.txt
success
$ curl -k https://localhost:4433/foo.txt
success
```
## 附：openssl s_server 总是需要tls证书 待续
```bash
work_dir=pem
host=localhost

# 自签名证书，做 ca
cd $work_dir
openssl req -new -x509 -subj "/CN=ca-host" -days 3650 -keyout ca-key.pem -nodes -out ca-crt.pem

```
# openssl req
man openssl req

此命令的功能：1. **生成证书请求文件** 2. 查看验证证书请求文件 3. 生成自签名证书

openssl req 命令，指定 -new 或者 -newkey，则生成请求文件，指定 -x509 则生成自签名证书。
都不指定，则期望读取证书请求文件（从 -in 参数，默认stdin）。
```
-new  表示生成证书签名请求。需要同时通过 -key 指定所用的私钥文件。
      如果没有指定 -key 选项，则自动生成密钥对，此时指定 -newkey 可以控制密钥参数


-newkey arg 选项指定生成新的证书请求和新的私钥。（比new，能指定新生成的私钥类型）
    指定了此选项，默认带上-new（即生成请求文件），除非显式指定 -x509

-x509

-in filename    指定从何处读取输入密钥/证书请求文件。默认从标准输入。仅当没有指定
  创建选项（-new，-newkey，-x509）的时候才会读取证书请求文件。

```
## 选项
```
Usage: req [options]
Valid options are:
 -help               Display this summary
 -inform PEM|DER     Input format - DER or PEM
 -outform PEM|DER    Output format - DER or PEM
 -in infile          Input file
 -out outfile        Output file
 -key val            Private key to use
 -keyform format     Key file format
 -pubkey             Output public key
 -new                New request
 -config infile      Request template file
 -keyout outfile     File to send the key to
 -passin val         Private key password source
 -passout val        Output file pass phrase source
 -rand val           Load the file(s) into the random number generator
 -writerand outfile  Write random data to the specified file
 -newkey val         Specify as type:bits
 -pkeyopt val        Public key options as opt:value
 -sigopt val         Signature parameter in n:v form
 -batch              Do not ask anything during request generation
 -newhdr             Output "NEW" in the header lines
 -modulus            RSA modulus
 -verify             Verify signature on REQ
 -nodes              Don't encrypt the output key
 -noout              Do not output REQ
 -verbose            Verbose output
 -utf8               Input characters are UTF8 (default ASCII)
 -nameopt val        Various certificate name options
 -reqopt val         Various request text options
 -text               Text form of request
 -x509               Output a x509 structure instead of a cert request
                     (Required by some CA's)
 -subj val           Set or modify request subject
 -subject            Output the request's subject
 -multivalue-rdn     Enable support for multivalued RDNs
 -days +int          Number of days cert is valid for
 -set_serial val     Serial number to use
 -addext val         Additional cert extension key=value pair (may be given more than once)
 -extensions val     Cert extension section (override value in config file)
 -reqexts val        Request extension section (override value in config file)
 -precert            Add a poison extension (implies -new)
 -*                  Any supported digest
 -engine val         Use engine, possibly a hardware device
 -keygen_engine val  Specify engine to be used for key generation operations
```
## 配置
req 命令使用配置文件中的 `[ req ]` 节，对于 req 节中缺失的值，会去 default 中查找。

具体配置项，如下。

### input_password output_password
如果需要读取私钥且私钥有密码保护，input_password 指定私钥密码。
如果会生成公钥且需要为私钥设置密码保护，output_password 指定私钥密码。
命令行选项 -passin 和 -passout 可以覆盖这两个配置项。
### default_bits
如果会生成密钥，此选项指定密钥位数。缺省值 1024，允许最小值为 512。
命令行选项 -newkey 可以指定密钥位数，会覆盖此配置项。

### default_keyfile
当生成新密钥时，此配置想指定默认密钥文件路径，命令行选项 -keyout可以覆盖此配置。
不指定输出路径，缺省输出到标准输出。
### oid_file ？？不懂
### oid_section？？
### RANDFILE ？？
### encrypt_key
当生成新密钥时，是否设置密码保护，配置项为 no 时不设密码保护，为 yes 时设置密码保护。
encrypt_key = no 等价于命令选项 -nodes。
为了兼容，encrypt_rsa_key 配置项等价于此。

### default_md
设置默认摘要算法。所有 dgst 命令接收的摘要算法名称都可以。
可以被命令行选项覆盖。
某些签名算法（如 Ed25519, Ed448）的摘要算法是固定的，不受此配置项控制。

摘要算法举例：md4,md5,sha1,sha256,sha512,sha384。
### string_mask？？
一般用不到。
### req_extensions
指定证书请求中扩展段的信息。命令行选项 -reqexts 可覆盖此配置项。

具体配置参考 x509v3_config(5) 手册页。
### x509_extensions
在使用 -x509 生成证书时，此配置想指定扩展段的信息。命令行选项 -extensions 可覆盖此
配置项。
### prompt
和 distinguished_name 和 attributes 一起。
### utf8
如果设置为 yes，则使用 utf-8 编码解析字段值，无论是来自配置文件还是来命令行。
默认按ASCII 编码解析字段值。
### attributes？？
指定一些属性。当前 OpenSSL 的请求签名工具忽略这个配置项。
This specifies the section containing any request attributes: its format is the same as distinguished_name. Typically these may contain the
challengePassword or unstructuredName types. They are currently ignored by OpenSSL's request signing utilities but some CAs might want them.
### distinguished_name
生成证书请求或者生成证书时，DN 信息。单独描述。
## DN 信息
首先看prompt的值，如果为no，则直接读取配置文件中指定的值作为DN信息
```ini
CN=My Name
OU=My Organization
emailAddress=someone@somewhere.org
```

如果promp不是no，那么配置文件需要设置 DN 信息中各个字段的提示信息，格式如下
```ini
fieldName="prompt"
fieldName_default="default field value"
fieldName_min= 2
fieldName_max= 4
```
fieldName 对应输入提示语，如果用户输入空，则使用默认值，如果没有默认值则忽略这个字段。
即使设置了默认值，用户也可以输入 . 显式忽略这个字段。
字段的字符数必须位于 fieldName_min 和 fieldName_max 的范围内，同时可能有其他限制，
比如 CN 就只能是两个字符，且要求是可打印字符。

如果某个字段需要指定多个值，只有最后一个会生效，解决方法是搞个前缀，比如，字段
organizationName 第二个值可以通过`1.organizationName=value`的形式指定。
就是在字段名前面 xx. 前缀。

实际可使用的字段名称不是固定，但常见的名称都是支持的，比如：
commonName, countryName, localityName, organizationName, organizationalUnitName, stateOrProvinceName。

> The actual permitted field names are any object identifier short or long names. These are compiled into OpenSSL and include the usual values such as
commonName, countryName, localityName, organizationName, organizationalUnitName, stateOrProvinceName. Additionally emailAddress is included as well as name,
surname, givenName, initials, and dnQualifier.

> Additional object identifiers can be defined with the oid_file or oid_section options in the configuration file. Any additional fields will be treated as
though they were a DirectoryString.
## 调试
使用自定义配置文件的时候，有可能遇到如下报错：
```
unable to find 'distinguished_name' in config
problems making Certificate Request
```
很明显，是因为没有设置 distinguished_name。
可以把这个看作 openssl 的一个bug。

ps：验证操作不需要此配置，生成证书请求也不需要，但生成自签名证书是需要的。

# openssl x509
多用途证书工具。
- 查看证书内容
- 转换证书格式
- 签署证书请求（迷你ca）
- 编辑证书的信任设置 Q. edit certificate trust settings. 是什么？

选项太多，分成几个部分介绍。

-CA 签署证书
-signkey 自签名证书

没有 -CA 也没有 -signkey，则是查看证书。

x509 命令没有配置文件段，也没有 -config 选项，但提供了 -extfile 和 -extensions 选项作为补充。
同样没有 -subj 选项。难怪这个签署证书时必须提供证书请求或者证书，因为它需要提取其中的配置
信息啊。

## 选项
### 输入输出和通用选项
* -help
* -inform PEM | DER
* -outform PEM | DER
* -in filename    输入文件路径，默认 stdin
* -out filename   输出文件路径，默认 stdout
* -digest         指定哈希算法。与签名或者展示选项配合，例如 -fingerprint，-signkey，-CA。
  dgst 命令支持的哈希名称都可以。不指定时，对于 -fingerprint 默认为 SHA1，对于 -signkey和 -CA 是默认配置，一般为 SHA256.
* -rand file      为随机数生成器提供随机数据的文件
* [-writerand file]   不知道
* -engine id      不知道
* -preserve_dates   签署证书时，指定证书有效期，与 -days 互斥。
### 查看选项
注：-alias 和 -purpose 也是展示选项，但放在 TRUST TESTING 中介绍了。
* -text   以文本形式展示证书信息，事无巨细，都展示
* -ext  extensions  文本形式展示证书中指定的扩展段信息
* -certopt option   与 -text 配合使用，定制输出格式。详见 TEXT OPTIONS 小节
* -noout    抑制证书回显。默认会输出PEM格式的证书信息
* -pubkey   以 PEM 格式输出整数的  SubjectPublicKeyInfo 信息段
* -modulus  输出证书中公钥的 modulu 信息
* -serial   输出证书序列号
* -subject_hash 输出证书所有者的“哈希”。方便形成索引，以便根据主体名称查找证书文件。大概长这个样子：c2d11598。
  Outputs the "hash" of the certificate subject name. This is used in OpenSSL to form an index to allow certificates in a directory to be looked up by
  subject name.
* -issuer_hash 证书颁发者的“hash”
* -ocspid     证书主题和公钥的 OCSP 哈希值
* -hask     是 -subject_hash 的别名，为了后向兼容
* -subject_hash_old   输出证书所有者的“哈希”，openssl 1.0.0 之前的哈希算法
* -issuer_hash_old    输出证书所有者的“哈希”，penssl 1.0.0 之前的哈希算法
* -subject    证书主体信息
* -issuer     证书颁发者信息
* -nameopt option 输出主体或者颁发者信息时的格式，NAME OPTIONS 小节
* -email  Outputs the email address(es) if any.
* -ocsp_uri Outputs the OCSP responder address(es) if any.
* -startdate  Prints out the start date of the certificate, that is the notBefore date.
* -enddate  Prints out the expiry date of the certificate, that is the notAfter date.
* -dates    Prints out the start and expiry dates of a certificate.
* -checkend arg 校验证书在 arg 秒之后是否会过期，如果过期，则退出状态非零。
* -fingerprint  计算并输出证书在 DER 格式下的完整证书的哈希值。这叫做指纹。指纹相同就可以认为证书相同。
*  -C  This outputs the certificate in the form of a C source file.
### Trust settings    待续
Q. 不知道这个怎么翻译才贴切。

Q. 看不懂这里的选项
### 签名选项
x509 命令可以签署证书和请求，所以叫着“迷你ca”。
* -signkey arg    使用指定的私钥或引擎对输入文件自签名。

  Q. 本来就是证书了，为什么还要签名？
  Ans: 如果输入的是证书，证书的 issuer 变成自己的 subject name，然后把公钥换成 -signkey 指定的密钥，再重置证书有效期。

  >   If the input file is a certificate it sets the issuer name to the subject name (i.e.  makes it self signed) changes the public key to the supplied value
  and changes the start and end dates. The start date is set to the current time and the end date is set to a value determined by the -days option. Any
  certificate extensions are retained unless the -clrext option is supplied; this includes, for example, any existing key identifier extensions.

  当输入文件是证书请求时，使用指定的私钥和请求中的 subject 名称生成自签名证书。
  Q. 当私钥和证书请求中的密钥不是一对的时候，也能生成证书吗？
  Ans: 能，指定会从指定的私钥提取公钥生成证书。换言之，证书请求中的公钥信息被摒弃了。

  Q. 证书序号呢？没提，我猜是随机生成大整数作为序号。

* -passin arg   私钥密码
* -clrext       删除原有证书的扩展段信息。一般，当使用另一个证书构造新证书时（如 -signkey 和 -CA）才用到这个选项，默认
                是会保留扩展段信息的。
* -keyform PEM|DER|ENGINE   使用 -signkey 选项是，此选项指定私钥的格式
* -days arg     指定证书有效天数，默认30天。与 -preserve_dates 互斥
* -x509toreq    Q. 不懂
* -req          默认，x509 期望输入证书文件，指定此选项则告诉 x509 输入的是证书请求而非证书。
* -set_serial n 使用 -signkey 或 -CA 选项时，可以使用此选项指定证书编号。此选项与 -CA 搭配时，序号文件（通过 -CAserial 或 -CAcreateserial 指定）
  会被忽略

* -CA filename    指定用于签发证书的ca证书，指定此选项后，x509 的行为就像一个“迷你CA”。从这个选项指定的证书的主体信息作为
  新证书的签发者信息。
  > The input file is signed by this CA using this option: that is its issuer name
  is set to the subject name of the CA and it is digitally signed using the CAs private key.
* -CAkey filename 指定用于签发证书的CA私钥。如果不指定这个选项，就从 -CA 指定的证书中提取私钥。
  Q. 证书里可以包含私钥信息吗？
* -CAserialfile filename  ca的证书序列号文件。当指定 -CA 选项签署证书时，会使用序列号文件。
                          文件只有一行，内容是一个整数，它是下一个可用的证书序列号。
                          签名时，取它作为新证书的序列号，然后把序列号加一再写回文件中。
                          默认，序列号文件的名称是证书基本名加上 .srl 后缀，比如 ca.pem 对应 ca.srl。
* -CAcreateserial    如果证书文件不存在就创建：新创建的文件内容是 02，而此时签发的证书序号为 1。
                     如果同时使用了 -CA 选项且序号文件不存在，则生成随机数字作为序号，这是推荐的做法。
  ps：使用 -CA 的时候，当文件不存在时，还是会创建的。
* -extfile filename   证书扩展段信息。如果不指定，则不向证书添加扩展信息。
* -extension section  扩展段名称。如果不指定，则扩展信息要在default段中指定，或者在default段中通过 extensions 选项指 section。
* -force_pubkey key   强制给用 key 做证书的公钥，而非证书请求中的公钥
# openssl ca
ca 小型 CA 应用程序。
需要四个文件，ca证书，ca私钥，序号文件，索引文件。

## 说明
是小型 CA 应用程序，可以
- 对各种格式的证书请求颁发证书
- 颁发 CRL
- 维护一个文本数据库，记录签发的证书和它们的状态
## 选项
挑感兴趣的
* -config filename  指定配置文件
* -name   section   指定要使用的配置节，即覆盖
* -in     filename  证书请求
* -ss_cert filename 将要用 CA 去签名的自签名证书。Q. 哎呦呵，已经是证书了，再签一次，效果是什么？
* -out    filename  证书输出路径，默认把证书输出到标准输出中。
* -outdir  dirname  存放签名证书的目录，证书名称是证书序列号的十六进制 + .pem 后缀
* -cert    filenamne CA 证书
* -keyfile filename  签发证书使用的私钥。Q. 这个私钥可以和 CA 证书不一致吗？
* -keyform PEM|DER   证书格式，默认PEM
* -key     password  私钥的密码。ps 命令可以看到完整的命令行，所以慎用。
* -selfsign   表示要进行自签名。此时如果 -keyfile 指定的私钥和证书请求中的公钥不匹配，就不会颁发证书。
              在有 -spkac、 -ss_cert 或 -gencrl 之一的时候，此选项被忽略。
              使用此选项的一个推论是，生成的自签名证书同样会出现在证书数据库中，且会和其它证书使用同样的序列号计数器。
* -passin  arg      密码。比 -key 要好一些
* -startdate date   证书有效期 YYYYMMDDHHMMSSZ 格式。
* -enddatea  date
* -days  arg        证书有效时长。此时取当前时刻作为证书起始日期，然后根据时长计算终止日期
* -md   alg         指定摘要算法
* -policy arg       对应配置文件的 policy 配置项
* -preserveDN       默认，DN 字段的顺序与 policy 中列出的顺序一致。指定此选项后，则与证书请求中的DN字段顺序一致。这是为了
                    兼容 IE。
* -batch            批处理模式
* -extensions section 签发证书时使用这个 section 的信息设置证书扩展段，当未指定 -extfile 时，缺省值为 x509_extensions。
                    如果没有出现任何扩展 section，则签发 V1 版本的证书，如果出现了（即使是空的），则签发 V3 证书。
* -extfile    file  附加配置文件，提供证书扩展信息，使用 default section，除非指定了 -extensions 选项
                    替换默认的 x509_extensions 节整体（如果有），不是合并。
* -subj       arg   覆盖证书请求中的 subject 信息，格式为 `/type0=value0/type1=value1/type2=....`。关键字可用 `\`
                    转义，空白字符会保留，value可以为空，此时对应的type不会出现在证书中
* -utf8
* -create_serial    从序号文件读取序号失败时，创建新的随机序号作为下一个序号。
                    Q. 意思是会写入序号文件吗？不是，只要文件存在，就不再生成序号，如果文件内容不合规，则报错。
                    仅当序号文件不存在的时候才会生成序号。
* -rand_serial      随机生成大整数做证书序号，忽略序号文件。

## CRL 选项 略……看不懂
## 配置文件
如果指定了 -name，就是用它指定的 section，否则取 [ ca ] 或者 default 中的 default_ca 指定的 section。
此外，会直接读取 [ ca ] 中的 RANDFILE，preserver、msie_hack 这三个选项的值（如果有的话），但 RANDFILE 这个，可能是个
bug，将来版本未必如此。

许多配置项都有等价的命令行选项，同时出现时，命令行选项优先级更高，此外，对于必选配置项，必须在配置文件或者命令行选项中
提供值。

挑感兴趣的。

* new_certs_dir    必选，对应 -outdir
* certificate      必选，对应 -cert
* private_key      必选，对应 -keyfile
* default_days     对应 -days
* default_startdate 对应 -startdate，若未指定，则取当前时间。
* default_enddate   对应 -enddate，此选项和 default_days 必须提供一个。Q. 同时指定，那个会生效？
* default_md       必选，对应 -md 选项。但签名算法不需要哈希时（比如 Ed25519和Ed448），此选项不是必选。
* database         必选，文本数据库文件路径，没有对应的命令行选项。此文件初始时可以为空。
                   Q. 有缺省值吗？会自动创建吗？
* unique_subject   缺省为 yes，建议设为no。如果为yes，则数据库中记录的有效证书的subject必须唯一。如果为no，则可以重复。
                   为了兼容旧版（0.9.8），缺省值为yes。
                   证书的subject可以为空，多个证书的subject为空，不算重复。
* serial           必选，序号文件，它包含下一个可用的证书需要，hex 形式。此文件必须存在且包含有效的序号。
* x509_extensions  对应 -extensions。
* preserve         对应 -preserveDN
* policy           对应 -policy
* copy_extensions  决定如何处理证书请求中的 extensions 字段。不设置此选项或者设为 none，忽略证书请求中扩展信息。
                   设置为 copy，则复制请求中的扩展字段到证书中，但已经有的不复制；copyall，全部复制，如果已经有的，用证书请求
                   中的覆盖它。
                   此字段主要用于允许证书请求提供特定扩展字段，如 subjectAltName。

                   请阅读 WARNINGS

```
[ CA_default ]
x509_extensions = usr_cert              # The extensions to add to the cert

[ usr_cert ]
basicConstraints=CA:FALSE
nsComment                       = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
```
## policy 格式
policy 包含若干变量，对应由证书的 DN 字段名称构成，每个变量可以取值为
- match   要求字段值必须出现且和证书中的值一致。？？不明白。
- supplied  要求字段值必须出现
- optional  字段值可以出现

任何没有列出的字段，会静默删除。除非指定了 -preserveDN 选项，但这是个怪异的行为，而非程序本意。
PS -preserveDN 的这个效果可能是个bug？

```
[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
```
## 关于v3扩展段
默认，ca -> ca_default 的 v3_extensions 指定扩展段对应的节。
或者 -extensions 命令行选项指定扩展段对应的节。

Q. 指定 -extfile 之后会如何？
Ans：见 “关于 -extfile 和 -extensions”

ca 只能签发证书不能生成签名请求，-extfile 和 -extensions 指定 v3 扩展字段。
不指定 -extfile，仅指定 -extensions，覆盖主配置文件的 x509_extensions 配置项，
从主配置文件中找 -extensions 指定的 section。
指定了 -extfile，不指定 -extensions，则使用 -extfile 中的默认节作为 v3 扩展字段配置
（Q. 可以包含无关字段吗？），

## 关于database和serial选项

- 数据库文件必须手动创建，哪怕是空的。
- 会提问是否签名，是否提交，提交选n，会取消签发证书。
- 序号文件可以交由 ca 创建，指定 -create_serial 即可。
  但如果没有指定 -create_serial，会尝试只读模式打开序号文件，文件不存在，会报告失败。

ca 会尝试只读模式打开序号文件，文件不存在，会报告失败。
```bash
rm ca/* -rvf && mkdir ca/certs && touch ca/index.txt

openssl ca -in dist/server.csr -cert dist/ca-root.cert -keyfile dist/ca-root.key -passin pass:123456 \
  -subj '/CN=user' \
  -out dist/server.cert
```

文件存在，但为空，会报错，载入序号失败 unable to load number from ca/serial
```bash
rm ca/* -rvf && mkdir ca/certs && touch ca/index.txt
touch ca/serial
openssl ca -in dist/server.csr -cert dist/ca-root.cert -keyfile dist/ca-root.key -passin pass:123456 \
  -subj '/CN=user' \
  -out dist/server.cert
```
文件存在，手动写入序号 1
同样报错，

```
unable to load number from ca/serial
:short line:../crypto/asn1/f_int.c:140:
```
```bash
rm ca/* -rvf && mkdir ca/certs && touch ca/index.txt
echo 1 > ca/serial
openssl ca -in dist/server.csr -cert dist/ca-root.cert -keyfile dist/ca-root.key -passin pass:123456 \
  -subj '/CN=user' \
  -out dist/server.cert
```
文件存在，手动写入长一点的序号，可以了
```bash
rm ca/* -rvf && mkdir ca/certs && touch ca/index.txt
echo 10000000000000000000000000 > ca/serial
openssl ca -in dist/server.csr -cert dist/ca-root.cert -keyfile dist/ca-root.key -passin pass:123456 \
  -subj '/CN=user' \
  -out dist/server.cert
```

文件不存在，指定 -create_serial，
会自动创建文件，随机生成序号，把下一个序号写入
```bash
rm ca/* -rvf && mkdir ca/certs && touch ca/index.txt

openssl ca -in dist/server.csr -cert dist/ca-root.cert -keyfile dist/ca-root.key -passin pass:123456 \
  -subj '/CN=user' \
  -out dist/server.cert \
  -create_serial
```
序号文件存在, 指定 -create_serial，正常
```bash
rm ca/* -rvf && mkdir ca/certs && touch ca/index.txt

openssl ca -in dist/server.csr -cert dist/ca-root.cert -keyfile dist/ca-root.key -passin pass:123456 \
  -subj '/CN=user' \
  -out dist/server.cert \
  -create_serial
```
指定 -create_serial，且序号文件存在，但文件为空
报错：short line:
```bash
rm ca/* -rvf && mkdir ca/certs && touch ca/index.txt
touch ca/serial
openssl ca -in dist/server.csr -cert dist/ca-root.cert -keyfile dist/ca-root.key -passin pass:123456 \
  -subj '/CN=user' \
  -out dist/server.cert \
  -create_serial
```

可以指定 -rand_serial，随机生成序号，若序号文件不存在会自动创建，还会把下一个序号写入；
若序号文件存在，也会随机生成序号，然后把下一个序号写入。

```bash
rm ca/* -rvf && mkdir ca/certs && touch ca/index.txt

openssl ca -in dist/server.csr -cert dist/ca-root.cert -keyfile dist/ca-root.key -passin pass:123456 \
  -subj '/CN=user' \
  -out dist/server.cert \
  -rand_serial
```
## 关于 -extfile 和 -extensions
总结：指定 -extfile，则查找 extensions 时就完全屏蔽主配置文件了。

默认，使用 x509_extensions 字段指定的段作为扩展信息
```bash
rm -rvf ca/* && mkdir -p ca/certs && touch ca/index.txt
openssl ca -config conf.d/server-cert.conf -batch \
  -in dist/server.csr \
  -keyfile dist/ca-root.key -cert dist/ca-root.cert \
  -passin pass:$PASSWD \
  -create_serial \
  -out server.cert


alias show='openssl x509 -in server.cert -noout -text -certopt no_pubkey,no_sigdump'
```
指定 -extensions，会覆盖 x509_extensions 选项的值
```bash
rm -rvf ca/* && mkdir -p ca/certs && touch ca/index.txt
openssl ca -config conf.d/server-cert.conf -batch \
  -in dist/server.csr \
  -keyfile dist/ca-root.key -cert dist/ca-root.cert \
  -passin pass:$PASSWD \
  -create_serial \
  -out server.cert \
  -extensions ext2
```
指定 -extfile，则只从此文件读取扩展信息
```bash
rm -rvf ca/* && mkdir -p ca/certs && touch ca/index.txt
openssl ca -config conf.d/server-cert.conf -batch \
  -in dist/server.csr \
  -keyfile dist/ca-root.key -cert dist/ca-root.cert \
  -passin pass:$PASSWD \
  -create_serial \
  -out server.cert \
  -extfile conf.d/ext3.conf
```

指定多个 -extfile，会合并这些 -extfile 中的扩展信息
```bash
rm -rvf ca/* && mkdir -p ca/certs && touch ca/index.txt
openssl ca -config conf.d/server-cert.conf -batch \
  -in dist/server.csr \
  -keyfile dist/ca-root.key -cert dist/ca-root.cert \
  -passin pass:$PASSWD \
  -create_serial \
  -out server.cert \
  -extfile conf.d/ext3.conf \
  -extfile conf.d/ext4.conf
```
同时指定 -extfile 和 -extensions，如果 -extensions 指定的段在主配置文件中
而不在 -extfile 中，则报错
```bash
ERROR: adding extensions in section ext2
rm -rvf ca/* && mkdir -p ca/certs && touch ca/index.txt
openssl ca -config conf.d/server-cert.conf -batch \
  -in dist/server.csr \
  -keyfile dist/ca-root.key -cert dist/ca-root.cert \
  -passin pass:$PASSWD \
  -create_serial \
  -out server.cert \
  -extensions ext2 \
  -extfile conf.d/ext3.conf \
  -extfile conf.d/ext4.conf
```
同时指定 -extfile 和 -extensions，且 -extensions 指定的段在 -extfile 中，则可以
```bash
rm -rvf ca/* && mkdir -p ca/certs && touch ca/index.txt

cat > ca/ext4.conf <<EOF
[ ext4 ]
extendedKeyUsage = clientAuth
EOF

openssl ca -config conf.d/server-cert.conf -batch \
  -in dist/server.csr \
  -keyfile dist/ca-root.key -cert dist/ca-root.cert \
  -passin pass:$PASSWD \
  -create_serial \
  -out server.cert \
  -extensions ext4 \
  -extfile ca/ext4.conf
```

同时指定多个 -extfile 和一个 -extensions，则要求各个 -extfile 都包含
-extensions 指定的节
```bash
ERROR: adding extensions in section ext4

rm -rvf ca/* && mkdir -p ca/certs && touch ca/index.txt

cat > ca/ext4.conf <<EOF
[ ext4 ]
extendedKeyUsage = clientAuth
EOF

cat > ca/ext5.conf <<EOF
keyUsage = dataEncipherment
extendedKeyUsage = serverAuth
EOF

openssl ca -config conf.d/server-cert.conf -batch \
  -in dist/server.csr \
  -keyfile dist/ca-root.key -cert dist/ca-root.cert \
  -passin pass:$PASSWD \
  -create_serial \
  -out server.cert \
  -extensions ext4 \
  -extfile ca/ext4.conf \
  -extfile ca/ext5.conf
rm -rvf ca/* && mkdir -p ca/certs && touch ca/index.txt


cat > ca/ext4.conf <<EOF
[ ext4 ]
extendedKeyUsage = clientAuth
EOF

cat > ca/ext5.conf <<EOF
[ ext4 ]
keyUsage = dataEncipherment
extendedKeyUsage = serverAuth
EOF

openssl ca -config conf.d/server-cert.conf -batch \
  -in dist/server.csr \
  -keyfile dist/ca-root.key -cert dist/ca-root.cert \
  -passin pass:$PASSWD \
  -create_serial \
  -out server.cert \
  -extensions ext4 \
  -extfile ca/ext4.conf \
  -extfile ca/ext5.conf
```
# Demo: 生成证书签名请求文件
请求文件，唯一的入口 openssl req

req 生成证书签名请求文件时，可以不需要外部配置。

genrsa 命令生成的密钥默认不设密码保护，指定 -aes256 等密码名称，可以同时为密钥设置密码。
req 命令生成的密钥要求提供密码，还要求不小于 4 个字符，指定 -nodes 可以省略密码
## 已有密钥对，生成请求文件
设私钥文件为 server-key.pem
```bash
openssl genrsa -out server-key.pem
openssl req -new -key server-key.pem -out server-csr.pem -subj "/CN=example.com"
```
这里的 `-new` 和 `-key server-key.pem` 是必须的参数。

-new  表示生成证书签名请求。

如果不指定 subj 选项，会交互式提问，要求填写 DN 信息。

## 没有密钥对，直接生成密钥和请求文件
```bash
openssl req -new -newkey rsa:2048 -keyout server-key.pem -out server-req.pem -nodes -subj "/CN=example.com"
# 可以省略 -newkey 或 -new 二者之一
openssl req -new -keyout server-key.pem -out server-req.pem -nodes -subj "/CN=example.com"
openssl req -newkey rsa:2048 -keyout server-key.pem -out server-req.pem -nodes -subj "/CN=example.com"
```
使用 -new 选项时，如果没有指定 -key，则自动生成新密钥对。
使用 -newkey 时，如果没有指定 -x509，则隐含为 -new 选项。

## 生成请求文件无需默认配置
req 生成证书签名请求文件时，可以不需要外部配置。
```
openssl req -config /dev/null -new -newkey rsa:2048 -keyout server-key.pem -out server-req.pem -nodes -subj "/CN=example.com"
```

# 生成自签名证书
openssl req 的 -x509 选项可用于生成自签名证书。
自签名证书的序列号，默认自动生成一个比较大的随机序列号。

```
req -x509
    This option outputs a self signed certificate instead of a certificate request. This is typically used to generate a test certificate or a self signed root
    CA. The extensions added to the certificate (if any) are specified in the configuration file. Unless specified using the set_serial option, a large random
    number will be used for the serial number.

    If existing request is specified with the -in option, it is converted to the self signed certificate otherwise new request is created.
```
openssl x509 的 -signkey 也能生成自签名证书，当然，有点别扭。x509 主要创建正常的证书的。

Q. 或许，ca 命令也能自签名？
Ans: 能。

关于扩展字段。req 签发证书时，设置扩展字段的方式：
1. -addext
2. -extensions section（等价于-reqexts section）选项指定配置文件中的小节作为扩展段信息
  Q. 默认，扩展段的对应的配置节名称是什么？

ca和x509 命令签发证书时，设置扩展字段的方式：
1. -extfile filename
2. -extensions section

Q. 是不是意味着，x509 签发证书，不能撤销证书，而 ca 命令能。

## 没有密钥，直接生成自签名证书
```bash
openssl req -new -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-crt.pem -nodes -subj "/CN=example.com" -days 365

# -new 可以省略，因为 -x509 引出 -new
# 如果采用默认密钥配置 -newkey 也可以省略
# 默认有效期是一个月，仅为了演示的话，-days 365 也可以省略
openssl req -x509 -keyout ca-key.pem -out ca-crt.pem -nodes -subj "/CN=example.com"
```
PS：自签名证书，需要 distinguished_name 选项。安装 openssl 包时的默认配置就够了，有这个选项。
## 已有密钥对，生成自签名证书
使用 -x509 + -key 即可。
```bash
openssl req -x509 -key ca-key.pem -days 100 -out ca-crt.pem -subj "/CN=ca-host"
```

## 已有密钥对和请求文件，生成自签名证书
```bash
openssl req -x509 -in ca-csr.pem -key ca-key.pem  -out ca-crt.pem
```

而且在这种情形下无法指定 -subj 了，只能使用请求文件中的。
```bash
$ openssl req -x509 -in ca-csr.pem -subj "/CN=ca-host" -key ca-key.pem
Cannot modify certificate subject
```

或者使用 openssl x509 也可以
```bash
openssl x509 -req -in ca-csr.pem -signkey ca-key.pem -out ca-crt2.pem -days=99
```

## 只有请求文件，没有私钥，无法生成自签名证书
```bash
$ openssl req -x509 -in ca-csr.pem -subj "/CN=ca-host"
you need to specify a private key
```

# 签发证书
假设已有 ca-key.pem 和 ca-crt.pem，现提供证书请求文件 server-csr.pem，要求签发证书 server-crt.pem。

## x509 的 -CA 系列选项

```bash
openssl x509 -req -in server-csr.pem -CA ca-crt.pem -CAkey ca-key.pem -CAcreateserial \
  -days 365 -out server-crt.pem
```
这样是 1.0 的版本。

要生成 v3 格式的证书，增加 -extfile 选项。
```bash
openssl x509 -req -in server-csr.pem -CA ca-crt.pem -CAkey ca-key.pem -CAcreateserial  \
   -days 365 -out server-crt.pem \
   -extfile /etc/ssl/openssl.cnf \
   -extensions v3_req
```
Q. x509 的 -signKey 选项如何呢?

Q. 签发二级 CA 试试。
Q. 私钥的密码 -passin 选项
Q. 使用 ca 命令，
Q. 使用 gpg 统一管理根密钥。

Q. 有了 x509 为什么还要ca命令？
Ans：
1. ca 命令只是为了演示一个基础的CA程序应当如何做，它不是专业的CA。
2. ca 命令比 x509 功能更多，比如crl。
## ca 命令

# openssl dhparam
[openssl dhparam(密钥交换) - 骏马金龙 - 博客园](https://www.cnblogs.com/f-ck-need-u/p/7103791.html)

2021-11-05

用于生成和管理dh文件。dh(Diffie-Hellman)是著名的密钥交换协议，或称为密钥协商协议，
它可以保证通信双方安全地交换密钥。但注意，它不是加密算法，所以不提供加密功能，仅仅
只是保护密钥交换的过程。在openvpn中就使用了该交换协议。关于dh算法的整个过程，见下文。

openssl dhparam命令集合了老版本的openssl dh和openssl gendh，后两者可能已经失效了，
即使存在也仅表示未来另有用途。

注意，dh协议文件生成速度随长度增长而急剧增长，使用随机数种子可以加快生成速度。

例如：生成1024长度的交换协议文件，其消耗的时间2秒不到。
```bash
[root@xuexi tmp]# time openssl dhparam -out dh.pem 1024
real    0m1.361s
user    0m1.356s
sys     0m0.000s
```
但生成长度2048的交换协议文件用了 33 秒，可见长度增长会导致协议生成的时间急剧增长。
```bash
$ time openssl dhparam -out dh.pem 2048
Generating DH parameters, 2048 bit long safe prime, generator 2
This is going to take a long time

real    0m33.908s
user    0m33.708s
sys     0m0.200s
```

而使用了64位随机数种子的同样命令只需？秒钟。
```
[root@xuexi tmp]# time openssl dhparam -rand rand.seed -out dh.pem 2048
```

openssl命令实现的是各种算法和加密功能，它的cpu的使用率会非常高，再结合dhparam，
可以使得openssl dhparam作为一个不错的cpu压力测试工具，并且可以长时间飙高cpu使用率。

# demos
## demo：验证服务器证书是否与根 CA 证书匹配
命令是 `openssl verify -CAfile ca.crt server.crt`如果两个证书匹配，命令将返回 server.crt: OK
以上命令仅适用于 pem 格式。
对于 .p12 格式，请先将其转换为 pem 格式:`openssl pkcs12 -in server.p12 -out server.crt -nodes`

## 证书里的中文

DN 字段包含中文的时候，用openssl生成证书签名请求时，加上-utf8就行了
`openssl req -utf8 -config openssl_utf8.cnf -new -out server.req`
查看证书时，给 x509 指定 -nameopt utf8 选项即可。
如下：
````bash
openssl req -x509 -out ca2.cert -nodes -subj "/CN=test/description=你好" -utf8

$ openssl x509  -in ca2.cert -noout -subject
subject=CN = test, description = \E4\BD\A0\E5\A5\BD
$ openssl x509  -in ca2.cert -noout -subject -nameopt utf8
subject=CN=test, description=你好
````

## 证书请求，不能有 authorityKeyIdentifier
```
[ v3_req_for_root_ca ]
basicConstraints = critical,CA:TRUE,pathlen:3
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
keyUsage =  keyCertSign, cRLSign
```

140492245157184:error:22077079:X509 V3 routines:v2i_AUTHORITY_KEYID:no issuer certificate:../crypto/x509v3/v3_akey.c:103:
140492245157184:error:22098080:X509 V3 routines:X509V3_EXT_nconf:error in extension:../crypto/x509v3/v3_conf.c:47:name=authorityKeyIdentifier, value=keyid:always,issuer
