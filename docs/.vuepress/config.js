
const navConf = require("./config/navConf.js")
const sideBar = require("./config/sideBar.js")
module.exports = {
    lang: "zh-CN",
    title: "openssl笔记",
    description: "openssl命令行学习笔记c",
    base: "/note-openssl/",
    themeConfig: {
        navbar: navConf,
        sidebar: sideBar,
        sidebarDepth: 2,
        lastUpdated: true,
        repo: "https://github.com/xizhan1995/note-openssl",
        docsBranch: "master",
        docsDir: "/docs"
    }
}
