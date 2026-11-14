# 2FA Web Authenticator

基于 Web Crypto API 的端到端加密（E2EE）零知识双因素验证器（TOTP），支持全平台浏览器访问与 Cloudflare Serverless 云端同步。

---

## 核心特性

- **端到端零知识加密 (E2EE)**：主密码通过 Web Worker 进行 600,000 次 PBKDF2 迭代推导加密密钥，在本地进行 AES-256-GCM 加密，云端仅存储密文，无法获取明文内容。
- **免运维云端同步**：支持免费部署在 Cloudflare Workers / Pages，基于 KV 实现轻量化数据同步。
- **智能时钟校准 (RTT 网络延迟补偿)**：针对代理或 TUN 模式下的首包握手延迟，内置网络往返时间补偿与整秒截断校准算法，避免因网络延迟拉偏本地时钟导致验证码计算错误。
- **多算法支持**：
  - RFC 6238 标准（SHA1、SHA256、SHA512，支持 6 位或 8 位数字）
  - Steam Guard 特殊 5 位字符动态口令
- **便捷导入与导出**：
  - 支持直接截屏或上传 QR 二维码图片识别
  - 支持导入 Google Authenticator 导出的 `otpauth-migration://` 格式迁移数据
  - 支持标准化 JSON 格式批量导入、排重与导出备份
- **完整离线与 PWA 支持**：配置 Web App Manifest 和 Service Worker，支持离线计算和安装到桌面或移动设备主屏幕。
- **原生极简设计**：自适应暗色/亮色主题，数字等宽（Tabular Nums）防抖动显示，环形倒计时动画。

---

## 架构与安全模型

```
[ 用户端浏览器 ]
  │
  ├─ 1. 用户输入主密码 (ADMIN Secret)
  ├─ 2. Web Worker: PBKDF2 (600,000 轮) -> 生成 AES-256-GCM 密钥 (K_enc)
  ├─ 3. 本地加解密: 账号与密钥数据明文只在前端内存中处理
  │
  ▼ 发送带有 Bearer Token 的加密密文 (密文 + 随机 IV)
[ Cloudflare Workers / KV ]
  │
  └─ 仅验证鉴权并存储单例加密 JSON，服务端对具体 2FA 密钥无感知
```

---

## 部署指南

### 方式一：Cloudflare Pages / Workers 自动部署（推荐）

1. 将本项目 Fork 或推送至您的 GitHub / GitLab 仓库。
2. 登录 [Cloudflare 控制台](https://dash.cloudflare.com/)，依次点击 **Workers 和 Pages** -> **创建应用程序** -> **Pages**。
3. 连接您的 Git 仓库并选择该项目：
   - **构建命令**：`npm run build`
   - **输出目录**：`dist`
4. 创建 KV 命名空间：
   - 在控制台中点击 **Workers 和 Pages** -> **KV** -> **创建命名空间**，名称命名为 `VAULT_KV`。
5. 绑定 KV 与环境变量：
   - 进入刚刚创建的 Pages 项目 -> **设置** -> **函数** -> **KV 命名空间绑定**：
     - **变量名称**：`VAULT_KV`
     - **KV 命名空间**：选择上一步创建的 `VAULT_KV`
   - 在 **设置** -> **环境变量** 中添加鉴权环境变量：
     - **变量名**：`ADMIN`
     - **值**：设置您的访问密码（此密码用于登录验证与云端鉴权，请妥善保存）
6. 重新触发一次部署即可访问。

### 方式二：Wrangler CLI 本地部署

1. 全局安装并登录 Wrangler：
   ```bash
   npm install -g wrangler
   wrangler login
   ```
2. 创建 KV 命名空间并记录返回的 `id`：
   ```bash
   wrangler kv:namespace create VAULT_KV
   ```
3. 更新 `wrangler.json` 中的 `id`，并通过命令行或控制台设置 Secret：
   ```bash
   wrangler secret put ADMIN
   ```
4. 构建并发布：
   ```bash
   npm run build
   npx wrangler deploy
   ```

---

## 本地开发与调试

```bash
# 安装依赖
npm install

# 启动本地开发服务 (支持 HMR)
npm run dev

# 编译生产资源到 dist 目录
npm run build
```

---

## 快捷键与常用操作

| 按键 / 操作 | 功能描述 |
| :--- | :--- |
| **点击卡片 / 验证码** | 自动复制动态验证码至剪贴板，并在 30 秒后自动清空剪贴板防泄露 |
| **`/` 键** | 快速聚焦搜索框，按平台名称或账号快速过滤 |
| **`Esc` 键** | 快速关闭当前打开的弹窗；若在主界面则快速锁定加密库 |
| **`?` 说明图标** | 打开使用说明与排错指南弹窗 |

---

## 常见问题与排错

### Q1：开启代理软件（TUN 模式）后，生成的验证码在目标网站提示错误？
1. **原理**：TOTP 验证码基于 UTC 时间戳计算（默认每 30 秒切换一次）。开启 TUN 模式或代理节点时，由于网络首包握手延迟，若简单拿服务端时间减去客户端接收时间，会产生数秒的人为负偏移。
2. **已内置机制**：系统已内置 RTT 往返网络延迟补偿算法，若网络偏差在正常容差范围（±2.5 秒内）会优先信任本地时钟。
3. **彻底解决**：如果验证码仍然对不上，通常是本地计算机系统时钟本身出现了漂移（Clash/Sing-box TUN 模式容易拦截 Windows 的 NTP UDP 123 端口）：
   - 在 Windows 系统中打开 **设置 -> 时间和语言 -> 日期和时间**；
   - 点击 **“立即同步”**，确保系统时钟完全校准即可恢复正常。

### Q2：提示“安全环境受限：必须使用 https:// 或 localhost 访问才能使用加密功能”？
现代浏览器的 Web Crypto API（如 `window.crypto.subtle`）出于安全规范，**强制要求在安全上下文（Secure Context）中运行**。请确保通过 `https://` 域名或 `localhost` 访问，普通的 `http://ip` 将被浏览器限制加解密功能。

### Q3：忘记主密码（ADMIN）如何处理？
因本系统采用端到端零知识加密，云端仅存有经 AES-256-GCM 封装的密文，无法找回或重置明文密码。建议定期使用**“导出”**功能保存一份未加密或离线归档的 JSON 数据存放在物理离线设备中。

---

## 开源协议

MIT License
