# 固件分析台 Firmware Bench

面向路由器 / 摄像头固件的**本地**安全分析工作台。替代手工 `binwalk` + `strings`,在浏览器里完成结构解析、文件系统浏览、风险发现、版本对比与报告导出。

- **全本地运行**:后端只监听 `127.0.0.1`,镜像与中间数据全部落在工作区 `data/`,不发起任何对外请求。
- **TypeScript 全栈**:Node + Express 后端,React + Vite 前端。

## 快速开始

```bash
npm install
npm run dev          # 同时启动后端(8787)与前端(5173),浏览器打开 http://localhost:5173
```

其它命令:

```bash
npm run gen:samples  # 在 data/samples 生成 5 个测试固件
npm test             # 端到端断言(51 项:识别/破解/漏洞/对比/报告/容错)
npm run build:web    # 构建前端到 dist/web
npm start            # 仅启动后端(构建后可由后端直接托管前端)
npm run typecheck    # 前后端类型检查
```

首次使用在「固件库」页点击 **生成并导入测试样本**,会导入 5 个内置固件;也可直接把固件拖进上传区。

## 五个页面

| 页面 | 能力 |
| --- | --- |
| 固件库 | 拖拽上传、SHA-256 去重信息、备注、样本导入、删除 |
| 结构解析 | 识别 uImage / TRX / SquashFS / CRAMFS / gzip / xz / LZMA,按比例画分区布局,展示头字段、估算大小与告警 |
| 文件系统 | 目录树展开、路径搜索、文本 / 十六进制双视图、符号链接、ELF 架构与导入函数 |
| 风险发现 | 硬编码口令、私钥/证书、shadow 弱哈希字典破解、危险配置、服务端口、组件 CVE 比对,可追加自定义字典重分析 |
| 报告 / 对比 | 导出独立内联 HTML 报告;两版本文件增删改 + 风险项差异对比 |

## 分析能力与实现要点

1. **容器与压缩**:uImage 64 字节头、TRX(HDR0)分区表解析;gzip 用 Node zlib,xz 用 `xz-decompress`(WASM),LZMA 用 `lzma` 并兼容 raw 流。解压失败只影响该段,不阻断整体。
2. **文件系统**:测试固件由内置生成器构造,外层是**真实的 SquashFS / CRAMFS 魔数与超级块**(结构页正常识别),超级块后带一个简单可靠的 FBFS1 目录表用于完整展开。遇到真实第三方镜像时仍解析超级块并给出明确提示。
3. **口令破解**:纯 TS 实现 `$1$` MD5-crypt、`$5$` SHA-256-crypt、`$6$` SHA-512-crypt 校验,以及裸 MD5/SHA1/SHA256;内置 40 条弱口令字典,可在前端追加词条。
4. **漏洞库**:离线 JSON,含 busybox / openssl / dropbear 代表性 CVE;版本比较支持 OpenSSL 字母后缀(如 `1.0.1f < 1.0.1g`,正确命中 Heartbleed)与受影响版本下界。
5. **健壮性**:所有解析按边界校验,损坏 / 截断镜像产生告警而不是抛栈,页面不白屏;分析整体异常也会保留库记录。

## 测试固件埋点

`gen:samples` 生成的样本均含已知问题,用于验证检测能力:

- `router-v1.bin`:uImage + gzip 内核 + SquashFS;硬编码口令、RSA 私钥、证书、3 个可破解 shadow 账号(+1 个强口令对照)、Telnet/UPnP/SNMP、`chmod 777`、`wget|sh`、老旧 busybox/openssl/dropbear(含 Heartbleed)。
- `router-v2.bin`:补丁版,升级组件、删除后门账号与私钥、关停 Telnet,用于差异对比。
- `camera-trx.bin`:TRX + LZMA + CRAMFS,ARM 架构 ELF。
- `corrupted.bin`:魔数正确但内部表损坏。
- `truncated.bin`:v1 截断 60%。

## 目录结构

```
src/
  shared/            前后端共享类型、魔数与工具
  server/
    analysis/        扫描、解压、文件系统、ELF、规则、哈希、漏洞库、对比、报告
    storage.ts       本地 data/ 存储
    index.ts         Express API(仅 127.0.0.1)
  web/               React 页面与组件
  tools/             样本生成器与端到端断言
```

## 安全边界

- 服务端不绑定公网网卡,无鉴权设计,假定仅本机单用户使用。
- 文件内容抽取上限 256KB / 个,大文件只保留元数据,避免内存膨胀。
- 报告为静态自包含 HTML,无外部资源,可离线打开或直接分发。
