# GA RealTime（多用户 + Google 一键登录）

已集成：
- 账号密码注册/登录/退出
- Google One Tap（Google Identity Services）一键登录
- TOTP 最小功能 + 分组（每用户隔离）

## 快速启动
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DJANGO_SECRET_KEY='your-secret'
export GOOGLE_CLIENT_ID='YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com'
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 0.0.0.0:8000
```
默认使用 sqlite数据库
打开 http://127.0.0.1:8000/auth/login/ 体验一键登录或账号登录。
# ToTP
