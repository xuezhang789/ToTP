# ToTP

基于 Django 的多用户 TOTP（基于时间的一次性密码）管理平台，支持密钥分组、批量导入导出、一次性分享链接、离线包生成等场景，适用于团队或个人集中管理 2FA 密钥。

---

## 项目概览

- **账户体系**：`accounts` 应用提供邮箱/密码注册登录、注销以及 Google One Tap 登录。
- **密钥管理**：`totp` 应用支持按分组保存密钥、软删除与回收站、批量导入（1Password / Bitwarden / Authy / 手动）和导出。
- **安全存储**：使用项目 `SECRET_KEY` 派生的 Fernet 密钥对 TOTP 秘钥进行对称加密，数据库泄露也无法直接获取明文。
- **验证码生成**：服务器端实时计算验证码与剩余时间，支持离线包生成与一次性分享链接。
- **REST API**：`/api/tokens/` 接口返回当前用户全部条目的验证码和剩余周期，便于外部脚本或

项目使用 Django 4.2、SQLite（默认）、`cryptography` 和 `google-auth` 等依赖，可根据需要切换到其它数据库或登录方案。

---

## 快速上手（本地开发）

### 1. 准备环境

- Python 3.10+
- 推荐 macOS / Linux，Windows 同样适用

```bash
git clone https://github.com/your-org/totp.git
cd totp
python -m venv .venv
source .venv/bin/activate  # Windows 使用 .venv\\Scripts\\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. 配置环境变量

可以直接导出，也可以在 `.env` 文件中维护并借助 `direnv` / `django-environ` 等工具加载。

```bash
export DJANGO_SECRET_KEY="replace-with-a-random-string"
export GOOGLE_CLIENT_ID="YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com"
# export DEBUG=false            # 生产环境请显式关闭
# export ALLOWED_HOSTS="example.com,totp.internal"
```

### 3. 初始化数据库

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

开发阶段使用内置的 SQLite 数据库 (`db.sqlite3`)；如需切换到 PostgreSQL / MySQL，请修改 `project/settings.py` 中的 `DATABASES` 配置或使用 `django-environ`/`dj-database-url` 等工具。

### 4. 启动服务

```bash
python manage.py runserver 0.0.0.0:8000
```

浏览器访问 [http://127.0.0.1:8000/](http://127.0.0.1:8000/) 即可体验仪表盘；登录页位于 `/auth/login/`。

---

## 生产部署指引

1. **依赖安装**：在干净的 Python 虚拟环境中执行 `pip install -r requirements.txt`，推荐使用 `pip-tools`/`uv` 进行锁定。
2. **环境变量**：必须设置 `DJANGO_SECRET_KEY`（强随机字符串）和 `ALLOWED_HOSTS`。如果使用 Google One Tap，确保 `GOOGLE_CLIENT_ID` 对应的域名与部署域名一致。
3. **数据库**：生产环境推荐 PostgreSQL。按照 Django 官方文档配置 `DATABASES` 后执行 `python manage.py migrate`。
4. **静态文件**：
   ```bash
   python manage.py collectstatic --noinput
   ```
   将 `static/` 目录交给 Nginx / CDN 提供服务。
5. **WSGI 服务**：使用 Gunicorn 作为示例：
   ```bash
   gunicorn project.wsgi:application --bind 0.0.0.0:8000 --workers 3
   ```
   搭配 Nginx 反向代理，实现 TLS 终端与静态资源缓存。
6. **计划任务**：
   - 回收站清理逻辑在用户访问相关页面时自动触发，如需定时任务可调用 `TOTPEntry.purge_expired_trash()`。
   - 监控命中率高的接口（如 `/api/tokens/`）时，可通过缓存层缓解并发压力。
7. **日志与安全**：
   - 根据需要配置 `LOGGING`，并开启 `SECURE_*`、`CSRF_COOKIE_SECURE`、`SESSION_COOKIE_SECURE` 等安全选项。
   - 推荐在反向代理层设置速率限制，防止暴力破解或链接枚举。

---

## 常用命令

- 运行测试：`python manage.py test`
- 创建本地管理员：`python manage.py createsuperuser`
- 导出密钥（后台功能）：管理界面或 `/totp/export/`
- 生成离线包：UI 中选择“导出离线包”按钮
- API 调用示例：

```bash
curl -H "Cookie: sessionid=..." https://your-domain/api/tokens/
```

响应内容包含每个条目的 `id`、当前验证码 `code`、验证码周期 `period` 和周期剩余秒数 `remaining`。

---

## 环境变量速览

| 变量名 | 描述 | 默认值 |
| ------ | ---- | ------ |
| `DJANGO_SECRET_KEY` | Django 密钥，亦用于加密 TOTP 密钥 | 开发环境内置的弱密钥（务必覆盖） |
| `DEBUG` | 调试模式 | `True` |
| `ALLOWED_HOSTS` | 允许访问的主机名列表 | `*` |
| `GOOGLE_CLIENT_ID` | Google One Tap 客户端 ID | `YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com` |

如需使用其它第三方登录或更严格的安全策略，可在 `project/settings.py` 中调整。

---


## 支持与反馈

如有问题、漏洞或功能建议，欢迎通过 Issue/PR 或邮件（`xuezhang789@gmail.com`）联系维护者。

