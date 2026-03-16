# 升级文档

本文档用于指导将 **2FA 在线工具** 从旧版本平滑升级到新版本。

## 1. 升级前准备

### 1.1 检查清单
- [ ] 确认当前版本号与目标版本号。
- [ ] 阅读目标版本的 [CHANGELOG.md](CHANGELOG.md)（如有），关注“破坏性变更 (Breaking Changes)”。
- [ ] 确认服务器磁盘空间充足。
- [ ] 安排维护窗口（建议在低峰期进行）。

### 1.2 备份策略（**至关重要**）
在执行任何升级操作前，**必须**备份数据库和关键配置文件。

**备份数据库 (PostgreSQL 示例)**:
```bash
pg_dump -U postgres totp > totp_backup_$(date +%Y%m%d).sql
```

**备份配置文件**:
```bash
cp .env .env.backup_$(date +%Y%m%d)
# 如果使用 SQLite，也备份 db.sqlite3
cp db.sqlite3 db.sqlite3.backup_$(date +%Y%m%d)
```

## 2. 标准升级流程

### 2.1 获取新代码
```bash
cd /var/www/totp
git fetch origin
git checkout main  # 或指定 tag: git checkout v1.2.0
git pull origin main
```

### 2.2 更新依赖
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### 2.3 数据库迁移
应用新的数据库变更。
```bash
python manage.py migrate
```
> **注意**: 如果遇到迁移错误，请立即停止并参考“回滚方案”。

### 2.4 静态文件更新
重新收集静态资源（CSS/JS）。
```bash
python manage.py collectstatic --noinput
```

### 2.5 重启服务
重启应用服务器以加载新代码。
```bash
sudo systemctl restart totp
# 可选：重启 Nginx（通常不需要，除非修改了 Nginx 配置）
# sudo systemctl restart nginx
```

## 3. 验证测试

升级完成后，请执行以下冒烟测试：

1. **登录验证**: 使用管理员账号登录系统。
2. **核心功能**:
   - 列表页是否加载正常（无 JS 报错）。
   - 验证码是否在动态刷新。
   - 尝试生成一个新的 TOTP 密钥（验证加密功能）。
3. **静态资源**: 检查页面样式是否正常，控制台是否有 404 错误。

## 4. 回滚方案

如果升级失败或发现严重 Bug，请按以下步骤回滚：

### 4.1 代码回滚
```bash
git checkout <上一版本commit_id>
# 或者
git checkout v1.1.0
```

### 4.2 依赖回滚
```bash
pip install -r requirements.txt
```

### 4.3 数据库回滚
如果新版本执行了 `migrate`，且包含了不可逆的数据结构变更，需恢复数据库备份。

**恢复数据库 (PostgreSQL)**:
```bash
# 警告：这将覆盖当前数据库
dropdb -U postgres totp
createdb -U postgres totp
psql -U postgres totp < totp_backup_YYYYMMDD.sql
```

### 4.4 重启服务
```bash
sudo systemctl restart totp
```

## 5. 版本兼容性说明

- **v1.x -> v1.x**: 通常兼容，只需执行标准升级流程。
- **跨大版本 (v1 -> v2)**: 可能包含数据结构重构或加密算法升级，请务必仔细阅读特定版本的迁移指南。
- **Python 版本**: 升级时请确认新版本是否提升了 Python 最低版本要求（如从 3.8 升至 3.10）。

## 6. 注意事项

- **加密密钥**: 绝对不要在升级过程中更改 `TOTP_ENC_KEY` 环境变量，否则会导致所有旧密钥无法解密。
- **Session**: 升级后，现有用户的登录 Session 可能会失效（取决于 Django 的 Session 变更），这是正常现象。
