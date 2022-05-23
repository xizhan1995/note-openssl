"use strict";(self.webpackChunknote_openssl=self.webpackChunknote_openssl||[]).push([[871],{7765:(l,e,i)=>{i.r(e),i.d(e,{data:()=>t});const t={key:"v-1473bf53",path:"/demo/",title:"Readme",lang:"zh-CN",frontmatter:{},excerpt:"",headers:[{level:2,title:"TSL/SSL 证书",slug:"tsl-ssl-证书",children:[]}],filePathRelative:"demo/Readme.md",git:{updatedTime:1653302293e3,contributors:[{name:"chenxizhan",email:"chenxizhan1995@163.com",commits:2}]}}},2139:(l,e,i)=>{i.r(e),i.d(e,{default:()=>r});const t=(0,i(6252).uE)('<h1 id="readme" tabindex="-1"><a class="header-anchor" href="#readme" aria-hidden="true">#</a> Readme</h1><ul><li>update,2022-05-23,chenxizhan1995@163.com</li></ul><p>OpenSSL 1.1.1k 25 Mar 2021</p><h2 id="tsl-ssl-证书" tabindex="-1"><a class="header-anchor" href="#tsl-ssl-证书" aria-hidden="true">#</a> TSL/SSL 证书</h2><p>生成非对称密钥不是目的，而是为了其它目的服务。</p><ol><li>生成证书请求文件 .csr</li></ol><ul><li>已有私钥</li><li>无私钥</li></ul><ol start="2"><li>生成自签证书 .crt</li></ol><ul><li>已有私钥和 .csr</li><li>已有私钥，无 .csr</li><li>无私钥，无 .csr</li></ul><ol start="3"><li>生成自签 CA 证书</li><li>签发证书</li></ol><ul><li>已有 csr</li></ul><ol start="5"><li>二级 CA 证书</li></ol><ul><li>生成二级 CA 证书的请求文件 .csr</li><li>签发二级 CA 证书</li></ul><ol start="6"><li>根 CA 证书到期后的更换：key 不变，证书换新（有效期更新）</li></ol><p>以上，背诵对应配置文件</p>',15),a={},r=(0,i(3744).Z)(a,[["render",function(l,e){return t}]])},3744:(l,e)=>{e.Z=(l,e)=>{const i=l.__vccOpts||l;for(const[l,t]of e)i[l]=t;return i}}}]);