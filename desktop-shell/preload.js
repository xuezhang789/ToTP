// 预加载脚本：向渲染进程暴露只读的应用信息，避免开启 Node 集成
const { contextBridge } = require('electron');
const pkg = require('./package.json');

contextBridge.exposeInMainWorld('totpDesktop', {
  version: pkg.version,
});
