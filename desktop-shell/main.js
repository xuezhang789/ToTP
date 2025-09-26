// 主进程：负责创建桌面窗口并加载 Web 应用
const { app, BrowserWindow, Menu, dialog, shell, net } = require('electron');
const path = require('path');

// 默认启动地址指向本地 Django 服务，可通过环境变量覆盖
const START_URL = process.env.TOTP_DESKTOP_START_URL || 'http://127.0.0.1:8000/';
let mainWindow = null;

// 检查服务是否可访问，便于在用户未启动后端时给出提示
function checkBackendReachable() {
  return new Promise((resolve) => {
    const request = net.request(START_URL);
    request.on('response', () => resolve(true));
    request.on('error', () => resolve(false));
    request.end();
  });
}

async function createWindow() {
  const reachable = await checkBackendReachable();
  if (!reachable) {
    dialog.showMessageBox({
      type: 'warning',
      title: '无法连接到服务',
      message: '未检测到正在运行的 ToTP 服务，请先执行 `python manage.py runserver`，然后重试。',
    });
  }

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    backgroundColor: '#0d6efd',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  mainWindow.loadURL(START_URL);
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  const template = [
    {
      label: '应用',
      submenu: [
        { role: 'reload', label: '重新加载' },
        { role: 'toggleDevTools', label: '切换开发者工具' },
        { type: 'separator' },
        { role: 'minimize', label: '最小化' },
        { role: 'close', label: '关闭窗口' },
      ],
    },
    {
      label: '帮助',
      submenu: [
        {
          label: '访问项目主页',
          click: () => shell.openExternal('https://2fa.97.cx/'),
        },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});
