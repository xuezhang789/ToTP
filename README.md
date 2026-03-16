# ToTP

基于 Django 的多用户 TOTP（基于时间的一次性密码）管理平台，支持密钥分组、批量导入导出、一次性分享链接、离线包生成等场景，适用于团队或个人集中管理 2FA 密钥。

---

## 项目概览

- **账户体系**：`accounts` 应用提供邮箱/密码注册登录、注销以及 Google One Tap 登录。
- **密钥管理**：`totp` 应用支持按分组保存密钥、软删除与回收站、批量导入（1Password / Bitwarden / Authy / 手动）和导出，现已支持团队共享空间，成员可按角色协同管理条目。
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
2. **环境变量**：必须设置 `DJANGO_SECRET_KEY`（强随机字符串）、`DJANGO_ALLOWED_HOSTS`（逗号分隔，禁止 `*`）以及 `TOTP_ENC_KEY` / `TOTP_ENC_KEYS`（用于加密存储 TOTP 密钥）。如果使用 Google One Tap，确保 `GOOGLE_CLIENT_ID` 对应的域名与部署域名一致。
3. **数据库**：生产环境推荐 PostgreSQL。按照 Django 官方文档配置 `DATABASES` 后执行 `python manage.py migrate`。
4. **静态文件**：
   ```bash
   python manage.py collectstatic --noinput
   ```
   将 `static/` 目录交给 Nginx / CDN 提供服务。
   - 如果启用了 `ManifestStaticFilesStorage`（或使用 WhiteNoise 的 manifest 模式），`{% static 'js/import_modal.js' %}` 这类引用会被解析到带 hash 的文件名（例如 `import_modal.<hash>.js`），因此**必须**在发布流程中执行 `collectstatic` 生成对应文件。
   - 项目内已增加静态资源安全护栏测试（扫描 `staticfiles/js/import_modal*.js` 中的高危 DOM 注入模式），建议在 CI 中保持开启。
   - `staticfiles/` 属于构建产物目录，建议只在发布/镜像构建阶段生成，并避免将旧产物与源码混用。
5. **WSGI 服务**：使用 Gunicorn 作为示例：
   ```bash
   gunicorn project.wsgi:application --bind 0.0.0.0:8000 --workers 3
   ```
   搭配 Nginx 反向代理，实现 TLS 终端与静态资源缓存。
6. **计划任务**：
   - 回收站清理逻辑在用户访问相关页面时自动触发，如需定时任务可调用 `TOTPEntry.purge_expired_trash()`。
   - 监控命中率高的接口（如 `/api/tokens/`）时，可通过缓存层缓解并发压力。
7. **日志与安全**：
   - 根据需要配置 `LOGGING`，并开启 `SECURE_*`、`CSRF_COOKIE_SECURE`、`SESSION_COOKIE_SECURE` 等安全选项（默认在 `DJANGO_DEBUG=false` 时会启用更严格的默认值）。
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
| `DJANGO_SECRET_KEY` | Django SECRET_KEY | `dev-secret-key-change-me`（生产必须覆盖） |
| `DJANGO_DEBUG` | 调试模式 | `True` |
| `DJANGO_ALLOWED_HOSTS` | 允许访问的主机名列表（逗号分隔） | `localhost,127.0.0.1,[::1]` |
| `TOTP_ENC_KEY` | TOTP 密钥加密主密钥（单把） | 空（生产必须设置） |
| `TOTP_ENC_KEYS` | TOTP 密钥加密备用密钥（多把，逗号分隔） | 空 |
| `DJANGO_CSP` | 是否启用 CSP（带 nonce 的 script-src） | 生产默认启用 |
| `DJANGO_CSP_REPORT_ONLY` | CSP 是否仅上报不拦截 | 开发默认启用 |
| `TOTP_EXTERNAL_TOOL_ENABLED` | 是否启用外部验证码工具 | 开发默认启用，生产默认关闭 |
| `TOTP_EXTERNAL_TOOL_ALLOW_SECRET_PREFILL` | 是否允许 `?secret=` 预填 | `False` |
| `DJANGO_TRUST_X_FORWARDED_FOR` | 是否信任 `X-Forwarded-For` 获取客户端 IP | `False` |
| `TOTP_EXPORT_ENCRYPTED_MAX_ENTRIES` | 加密导出单次最大条目数 | `2000` |
| `TOTP_EXPORT_OFFLINE_MAX_ENTRIES` | 离线包单次最大条目数 | `1000` |
| `GOOGLE_CLIENT_ID` | Google One Tap 客户端 ID | `YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com` |

如需使用其它第三方登录或更严格的安全策略，可在 `project/settings.py` 中调整。

---


## 支持与反馈

如有问题、漏洞或功能建议，欢迎通过 Issue/PR 或邮件（`xuezhang789@gmail.com`）联系维护者。
