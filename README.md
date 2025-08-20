# GA RealTime / ToTP

## 产品介绍
GA RealTime / ToTP 是一个基于 Django 的多用户 TOTP（基于时间的一次性密码）管理平台，主要特性包括：

- **账号密码注册 / 登录 / 退出**：通过 `accounts` 应用提供基础认证功能  
- **Google One Tap 一键登录**：支持使用 Google 身份凭证快速创建或绑定用户  
- **TOTP 密钥的分组管理与用户隔离**：允许按分组保存密钥，避免用户之间的交叉访问  
- **对称加密与动态验证码生成**：借助 `SECRET_KEY` 派生的 Fernet 密钥对存储数据进行加密，并按时间周期生成验证码与剩余时间  
- **REST API 获取当前验证码**：返回所有条目的实时验证码及周期剩余时间  
- **默认使用 SQLite 的快速启动流程**：无需额外数据库即可运行

---

## 源码部署方法

1. **克隆或下载项目源码后进入项目目录**

2. **创建并激活虚拟环境**
```bash
python -m venv .venv
source .venv/bin/activate
```

3. **安装依赖**
```bssh
pip install -r requirements.txt

```
4. **设置必要环境变量**
```bash
export DJANGO_SECRET_KEY="your-secret"
export GOOGLE_CLIENT_ID="YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com"
```

5. **初始化数据库并创建管理员账号**
```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

6. **启动开发服务器**
```bash
python manage.py runserver 0.0.0.0:8000
```

7. **访问项目**
浏览器访问 http://127.0.0.1:8000/auth/login/ 即可体验账号密码登录或 Google One Tap 登录。

8. **如果您有更好的建议或者想法，请与我联系**

xuezhang789@gmail.com



