# 部署文档

本文档详细说明如何在生产环境（Linux 服务器）部署 **2FA 在线工具**。

## 1. 环境要求

- **操作系统**: Ubuntu 20.04+ / Debian 11+ / CentOS 10+
- **Python**: 3.10 或更高版本
- **数据库**: PostgreSQL 13+ (推荐) 或 SQLite (仅限小规模使用)
- **Web 服务器**: Nginx
- **应用服务器**: Gunicorn
- **其他**: Redis (可选，用于缓存和会话)

## 2. 依赖安装

### 2.1 系统依赖
```bash
sudo apt update
sudo apt install python3-pip python3-venv python3-dev libpq-dev postgresql nginx git
```

### 2.2 项目代码
```bash
cd /var/www
git clone https://github.com/your-repo/ToTP.git totp
cd totp
```

### 2.3 Python 环境与依赖
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn psycopg2-binary  # 生产环境额外依赖
```

## 3. 配置步骤

### 3.1 环境变量
复制示例配置并修改：
```bash
cp project/.env.example .env  # 假设有 .env 文件，或直接设置系统环境变量
```

**必须设置的环境变量**（在 `/etc/systemd/system/totp.service` 或 `.env` 中）：

| 变量名 | 说明 | 示例值 |
|--------|------|--------|
| `DJANGO_SECRET_KEY` | Django 密钥（**必须复杂且保密**） | `django-insecure-xxxx...` |
| `DJANGO_DEBUG` | 调试模式（生产环境必须为 False） | `False` |
| `DJANGO_ALLOWED_HOSTS` | 允许访问的域名 | `2fa.example.com,1.2.3.4` |
| `DATABASE_URL` | 数据库连接串 | `postgres://user:pass@localhost:5432/totp` |
| `TOTP_ENC_KEY` | 密钥加密主键（生成方式见下文） | `base64-key...` |

**生成 TOTP_ENC_KEY**:
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

### 3.2 数据库初始化
```bash
# 确保数据库已创建
source venv/bin/activate
python manage.py migrate
```

### 3.3 静态文件收集
```bash
python manage.py collectstatic --noinput
```

### 3.4 创建管理员
```bash
python manage.py createsuperuser
```

## 4. 服务启动 (Gunicorn + Systemd)

创建 Systemd 服务文件 `/etc/systemd/system/totp.service`:

```ini
[Unit]
Description=gunicorn daemon for ToTP
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/totp
ExecStart=/var/www/totp/venv/bin/gunicorn \
          --access-logfile - \
          --workers 3 \
          --bind unix:/run/totp.sock \
          project.wsgi:application
Environment="DJANGO_SECRET_KEY=your-secret-key"
Environment="DJANGO_DEBUG=False"
Environment="TOTP_ENC_KEY=your-enc-key"
# 添加其他环境变量...

[Install]
WantedBy=multi-user.target
```

启动并启用服务：
```bash
sudo systemctl start totp
sudo systemctl enable totp
```

## 5. Nginx 配置

创建 Nginx 配置文件 `/etc/nginx/sites-available/totp`:

```nginx
server {
    listen 80;
    server_name 2fa.example.com;

    location = /favicon.ico { access_log off; log_not_found off; }
    
    # 静态文件
    location /static/ {
        root /var/www/totp;
    }

    # 主应用
    location / {
        include proxy_params;
        proxy_pass http://unix:/run/totp.sock;
    }
}
```

启用站点并重启 Nginx：
```bash
sudo ln -s /etc/nginx/sites-available/totp /etc/nginx/sites-enabled
sudo nginx -t
sudo systemctl restart nginx
```

建议使用 Certbot 配置 HTTPS：
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d 2fa.example.com
```

## 6. 验证测试

1. 访问 `https://2fa.example.com`，应看到登录页面。
2. 使用管理员账号登录。
3. 尝试添加一个 TOTP 密钥，确保加密存储正常（若 `TOTP_ENC_KEY` 配置错误会报错）。
4. 运行安全检查：
   ```bash
   python manage.py check --deploy
   ```

## 7. 监控与维护

- **日志查看**:
  - Gunicorn: `journalctl -u totp -f`
  - Nginx: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`
- **备份**: 定期备份 PostgreSQL 数据库和 `.env` 配置文件。
