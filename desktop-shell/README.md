# ToTP 桌面壳

基于 Electron 的简易桌面封装，可快速将现有的 ToTP 管理平台运行在独立窗口中。该壳不会改动后端逻辑，只负责：

- 为 PWA 提供独立窗口与应用菜单；
- 在启动前提醒用户先运行 Django 服务；
- 在需要时可直接打开开发者工具，辅助调试桌面环境。

## 本地启动

```bash
cd desktop-shell
npm install
npm start
```

默认会尝试访问 `http://127.0.0.1:8000/`，即本项目的开发地址。若需要指向线上环境，可在启动前设置：

```bash
TOTP_DESKTOP_START_URL="https://your-domain" npm start
```

## 与 PWA 的关系

Web 端已支持 PWA 与离线缓存。桌面壳只是对该 PWA 的简单打包，便于在 Windows/macOS 上提供独立入口；离线模式依旧由浏览器环境中的 Service Worker 负责。

若想打包为安装包，可在此目录继续接入 [`electron-builder`](https://www.electron.build/) 或 [`electron-forge`](https://www.electronforge.io/)，当前仓库保持最小可运行骨架，便于按需扩展。

## 如何打包分享给他人

### 方案一：使用 `electron-builder` 生成安装包（推荐）

1. 安装打包工具：
   ```bash
   cd desktop-shell
   npm install --save-dev electron-builder
   ```

2. 在 `package.json` 中增加打包脚本和基本配置，例如：
   ```json
   {
     "name": "totp-desktop-shell",
     "version": "0.1.0",
     "main": "main.js",
     "scripts": {
       "start": "electron .",
       "dist": "electron-builder"
     },
     "build": {
       "appId": "com.example.totp",
       "productName": "ToTP Desktop",
       "directories": {
         "output": "dist"
       },
       "files": [
         "main.js",
         "preload.js",
         "package.json"
       ]
     },
     "devDependencies": {
       "electron": "28.2.3",
       "electron-builder": "^24.6.4"
     }
   }
   ```

3. 执行打包：
   ```bash
   npm run dist
   ```

   生成的文件位于 `dist/` 目录，macOS 下通常是 `.dmg`/`.pkg`，Windows 为 `.exe`，Linux 为 `.AppImage` 或 `.deb`。

4. 将安装包发给对方即可使用；若对方要连接不同的后端，可在启动前设置 `TOTP_DESKTOP_START_URL` 指向自己的服务地址。

> 提示：最好在目标平台上打包（例如 Windows 安装包在 Windows 下制作），或使用 `electron-builder` 的跨平台镜像。

### 方案二：分享“便携版”目录

1. 保持本地已执行 `npm install`，确保 `node_modules` 目录齐全。
2. 将整个 `desktop-shell` 文件夹（含 `node_modules`）压缩后发给对方。
3. 对方解压后，运行：
   ```bash
   npm start
   ```
   或直接执行 `node_modules/.bin/electron .`。

这种方式无需额外打包，但体积较大，也要求对方本地具备 Node.js 环境。
