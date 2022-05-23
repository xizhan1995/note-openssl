"use strict";(self.webpackChunknote_openssl=self.webpackChunknote_openssl||[]).push([[252],{2922:(n,s,a)=>{a.r(s),a.d(s,{data:()=>e});const e={key:"v-7929afd8",path:"/origin/openssl3.html",title:"openssl 3.0",lang:"zh-CN",frontmatter:{},excerpt:"",headers:[{level:2,title:"与 1.1.1 的区别",slug:"与-1-1-1-的区别",children:[]},{level:2,title:"CeontOS 8 源码编译安装 openssl",slug:"ceontos-8-源码编译安装-openssl",children:[]}],filePathRelative:"origin/openssl3.md",git:{updatedTime:1637420898e3,contributors:[{name:"chenxizhan",email:"chenxizhan1995@163.com",commits:2}]}}},5855:(n,s,a)=>{a.r(s),a.d(s,{default:()=>x});var e=a(6252);const p=(0,e._)("h1",{id:"openssl-3-0",tabindex:"-1"},[(0,e._)("a",{class:"header-anchor",href:"#openssl-3-0","aria-hidden":"true"},"#"),(0,e.Uk)(" openssl 3.0")],-1),t=(0,e._)("p",null,"2021-11-09",-1),o=(0,e.Uk)('"3.0 正式版发布公告, 2021.09.07" '),l={href:"https://www.openssl.org/blog/blog/2021/09/07/OpenSSL3.Final/",target:"_blank",rel:"noopener noreferrer"},c=(0,e.Uk)("OpenSSL 3.0 Has Been Released!"),i=(0,e.Uk)('"版本号策略，基本采用 semver 风格" '),r={href:"https://www.openssl.org/policies/releasestrat.html",target:"_blank",rel:"noopener noreferrer"},u=(0,e.Uk)("/policies/releasestrat.html"),k={href:"https://www.openssl.org/docs/man3.0/man7/migration_guide.html",target:"_blank",rel:"noopener noreferrer"},b=(0,e.Uk)("迁移指南"),m={href:"https://www.openssl.org/docs/man3.0/man7/crypto.html",target:"_blank",rel:"noopener noreferrer"},d=(0,e.Uk)("在线man手册"),h={href:"https://github.com/openssl/openssl",target:"_blank",rel:"noopener noreferrer"},g=(0,e.Uk)("github仓库"),f={href:"https://www.feistyduck.com/library/openssl-cookbook/online/ch-openssl.html",target:"_blank",rel:"noopener noreferrer"},v=(0,e.Uk)("OpenSSL Cookbook"),_=(0,e.uE)('<h2 id="与-1-1-1-的区别" tabindex="-1"><a class="header-anchor" href="#与-1-1-1-的区别" aria-hidden="true">#</a> 与 1.1.1 的区别</h2><p>不全。</p><ul><li>API接口的接入方式发生了变化</li><li>命令行好像变化不大</li><li>版本号的语义发生了变化</li></ul><p>openssl 3 修复了<code>unable to find &#39;distinguished_name&#39; in config</code>的报错。</p><details class="custom-container details"><p>屏蔽掉配置文件时，调用 req 命令会报错 <code>unable to find &#39;distinguished_name&#39; in config</code></p><div class="language-bash ext-sh line-numbers-mode"><pre class="language-bash"><code>openssl req -config /dev/null <span class="token punctuation">\\</span>\n  -new -keyout demo.key <span class="token punctuation">\\</span>\n  -out demo.csr <span class="token punctuation">\\</span>\n  -subj <span class="token string">&#39;/CN=demo&#39;</span> -nodes\n</code></pre><div class="line-numbers"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br></div></div><p>输出</p><div class="language-bash ext-sh line-numbers-mode"><pre class="language-bash"><code>Generating a RSA private key\n<span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span>.+++++\n<span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span><span class="token punctuation">..</span>+++++\nwriting new private key to <span class="token string">&#39;demo.key&#39;</span>\n-----\nunable to <span class="token function">find</span> <span class="token string">&#39;distinguished_name&#39;</span> <span class="token keyword">in</span> config\nproblems making Certificate Request\n<span class="token number">140101273249152</span>:error:0E06D06C:configuration <span class="token function">file</span> routines:NCONF_get_string:no value:<span class="token punctuation">..</span>/crypto/conf/conf_lib.c:273:group<span class="token operator">=</span>req <span class="token assign-left variable">name</span><span class="token operator">=</span>distinguished_name\n</code></pre><div class="line-numbers"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br></div></div></details><h2 id="ceontos-8-源码编译安装-openssl" tabindex="-1"><a class="header-anchor" href="#ceontos-8-源码编译安装-openssl" aria-hidden="true">#</a> CeontOS 8 源码编译安装 openssl</h2><p>2021-11-09</p><p>当前（2021-11-20）常见的操作系统好像的软件库好像还是用的 openssl 1.1.x 版本，要使用 3.0.0，得要自己手动编译安装。</p><p>下载解压</p><div class="language-bash ext-sh line-numbers-mode"><pre class="language-bash"><code><span class="token function">curl</span> --limit-rate 5m -L -o openssl-3.0.0.tar.gz https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.0.tar.gz\n<span class="token function">tar</span> xzf openssl-3.0.0.tar.gz\n</code></pre><div class="line-numbers"><span class="line-number">1</span><br><span class="line-number">2</span><br></div></div><p>编译安装：</p><div class="language-bash ext-sh line-numbers-mode"><pre class="language-bash"><code>\n./config enable-fips\n\n<span class="token assign-left variable">con</span><span class="token operator">=</span><span class="token variable"><span class="token variable">$((</span>$<span class="token punctuation">(</span>nproc<span class="token punctuation">)</span><span class="token operator">+</span><span class="token number">1</span><span class="token variable">))</span></span>\n<span class="token function">make</span> -sj <span class="token variable">$con</span>\n<span class="token function">make</span> -sj <span class="token variable">$con</span> <span class="token function">install</span>\n</code></pre><div class="line-numbers"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br></div></div><p>某些操作系统预安装了 openssl，此时强烈建议把新版的 openssl 安装到单独的目录下，以免造成破坏。</p><blockquote><p>On some platforms OpenSSL is preinstalled as part of the Operating System. In this case it is highly recommended not to overwrite the system versions, because other applications or libraries might depend on it. To avoid breaking other applications, install your copy of OpenSSL to a different location which is not in the global search path for system libraries.</p></blockquote><div class="language-bash ext-sh line-numbers-mode"><pre class="language-bash"><code>\n./config --prefix<span class="token operator">=</span>/opt/openssl --openssldir<span class="token operator">=</span>/opt/openssl enable-fips\n\n<span class="token assign-left variable">con</span><span class="token operator">=</span><span class="token variable"><span class="token variable">$((</span>$<span class="token punctuation">(</span>nproc<span class="token punctuation">)</span><span class="token operator">+</span><span class="token number">1</span><span class="token variable">))</span></span>\n<span class="token function">make</span> -sj <span class="token variable">$con</span>\n<span class="token function">make</span> -sj <span class="token variable">$con</span> <span class="token function">install</span>\n\n<span class="token builtin class-name">echo</span> /opt/openssl/lib64 <span class="token operator">&gt;&gt;</span> /etc/ld.so.conf <span class="token operator">&amp;&amp;</span> ldconfig\n</code></pre><div class="line-numbers"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br></div></div><p>编译成静态库</p><div class="language-bash ext-sh line-numbers-mode"><pre class="language-bash"><code>\n./config --prefix<span class="token operator">=</span>/opt/ssl --openssldir<span class="token operator">=</span>/opt/ssl enable-fips no-shared\n\n<span class="token function">make</span> -sj <span class="token variable"><span class="token variable">$((</span>$<span class="token punctuation">(</span>nproc<span class="token punctuation">)</span><span class="token operator">+</span><span class="token number">1</span><span class="token variable">))</span></span>\n<span class="token function">sudo</span> <span class="token function">make</span> -sj <span class="token variable"><span class="token variable">$((</span>$<span class="token punctuation">(</span>nproc<span class="token punctuation">)</span><span class="token operator">+</span><span class="token number">1</span><span class="token variable">))</span></span> <span class="token function">install</span>\n\n<span class="token function">sudo</span> <span class="token function">ln</span> -s  /opt/ssl/bin/openssl /usr/local/bin/\n</code></pre><div class="line-numbers"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br></div></div><p>PS:我对手动编译安装Linux程序只会一些皮毛，又忍不住想尝试一下，怕不小心破坏了其它依赖于 openssl 库的程序的功能，所以 把它编译成静态库，仅供自己尝试。</p>',18),w={},x=(0,a(3744).Z)(w,[["render",function(n,s){const a=(0,e.up)("OutboundLink");return(0,e.wg)(),(0,e.iD)(e.HY,null,[p,t,(0,e._)("p",null,[o,(0,e._)("a",l,[c,(0,e.Wm)(a)])]),(0,e._)("p",null,[i,(0,e._)("a",r,[u,(0,e.Wm)(a)])]),(0,e._)("p",null,[(0,e._)("a",k,[b,(0,e.Wm)(a)])]),(0,e._)("p",null,[(0,e._)("a",m,[d,(0,e.Wm)(a)])]),(0,e._)("p",null,[(0,e._)("a",h,[g,(0,e.Wm)(a)])]),(0,e._)("p",null,[(0,e._)("a",f,[v,(0,e.Wm)(a)])]),_],64)}]])},3744:(n,s)=>{s.Z=(n,s)=>{const a=n.__vccOpts||n;for(const[n,e]of s)a[n]=e;return a}}}]);