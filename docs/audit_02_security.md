# 缺陷与安全审计报告

## 0. 结论摘要

- 当前代码以 Django 标准能力为主，整体攻击面较小，且单元测试覆盖较完整（约百级用例）。
- 未发现明显的高危漏洞模式（如：`eval/exec`、不安全反序列化、模板 `|safe` 大量滥用、raw SQL 拼接、CSRF 全局关闭等）。
- 风险主要集中在：
  - 生产配置的“必配项”（加密密钥轮换、CSP/安全 cookie）
  - 个别导出/列表类接口的性能边界（大数据量与 count/iterator 的取舍）
  - 前端交互层面缺少端到端 UI 自动化测试（可用性回归更依赖人工）

## 1. 审计方法与范围

### 1.1 覆盖范围

- 后端：`project/`、`accounts/`、`totp/`
- 表现层：`templates/`、`static/`
- 不包含：`staticfiles/`（第三方静态产物）、`totp/migrations/`（schema 演进脚本）、虚拟环境目录

### 1.2 静态扫描（受限版）

仓库未预置 SonarQube/ESLint/Bandit/SpotBugs 等工具链配置，本次采用：

- 规则化搜索：危险 API、模板逃逸、反序列化、命令执行、raw SQL、csrf_exempt 等
- 配置审查：`project/settings.py` 关键安全项
- 关键路径人工 review：认证/reauth、一次性链接生成/访问、团队权限、导入导出
- 单测回归：运行全量 `python manage.py test` 作为最低质量闸门

如需“标准 SAST 报告 + 热力图”，建议引入：

- Python：Bandit + Ruff（或 flake8）+ djlint（模板）
- JS：ESLint（若后续引入构建链，可接入）
- 质量平台：SonarQube（Python/JS/HTML）

## 2. 缺陷热力图（近似）

以“业务复杂度 + 攻击面 + 变更频率”粗略标注风险热区（非 SonarQube 真热力图）：

| 模块 | 热度 | 主要原因 |
|---|---:|---|
| `totp/views.py` | 高 | 业务入口集中、权限分支多、导入导出/链接/团队审计都在此 |
| `totp/models.py` | 中 | 领域模型与审计模型集中，字段/索引影响面大 |
| `accounts/views.py` | 中 | 认证、reauth、OneTap 登录 |
| `static/js/totp_list.js` | 中 | 列表页交互复杂、涉及 reauth 与局部刷新 |
| `static/js/one_time_audit.js` | 中 | 批量操作、reauth 跳转、状态处理 |
| `project/settings.py` | 中 | 生产安全项依赖配置正确性 |

## 3. 问题清单（含修复建议）

### SEC-01（中）TOTP 加密密钥回退到 `SECRET_KEY`

- **位置**：`totp/utils.py` 中 `_fernets()` 将 `settings.SECRET_KEY` 作为加密 key 列表的兜底（[utils.py:L15-L27](file:///Users/lingchong/Downloads/wwwroot/ToTP/totp/utils.py#L15-L27)）
- **风险**：生产环境若未设置 `TOTP_ENC_KEYS`，会导致密钥加密与 Django `SECRET_KEY` 耦合；轮换/应急处理复杂，且在配置迁移时更易造成“无法解密历史数据”的事故。
- **复现步骤**：
  1. 清空 `TOTP_ENC_KEYS`，仅依赖 `SECRET_KEY`
  2. 变更 `SECRET_KEY` 后尝试解密已有 `TOTPEntry.secret_encrypted` → 失败
- **修复建议**：
  - 生产模式（`DJANGO_DEBUG=false`）强制要求设置 `TOTP_ENC_KEYS`，并提供至少 1 个 key；轮换时在列表中前置新 key，保留旧 key 用于解密历史数据。
- **回归用例建议**：
  - 增加一个配置级测试：生产模式未配置 `TOTP_ENC_KEYS` 时启动失败（或给出明显 warning）。
- **可选一键补丁（推荐以“软失败 warning”起步）**：
  - 在 `project/settings.py` 读取配置后，若 `not DEBUG and not TOTP_ENC_KEYS`，打印告警或抛异常（需你确认是否允许生产启动硬失败）。

### SEC-02（中）reauth JSON 的 next 固定为列表页（非漏洞，但影响安全流程 UX）

- **位置**：`totp/views.py::_reauth_json`（[views.py:L122-L131](file:///Users/lingchong/Downloads/wwwroot/ToTP/totp/views.py#L122-L131)）
- **问题**：当 AJAX 请求触发 reauth_required 时，返回的 redirect 总是回到密钥列表页，无法精确回到触发点（尤其是团队审计、一次性链接审计等页面）。
- **影响**：用户更容易在“确认后返回的页面”迷失，造成误操作或重复操作。
- **修复建议**：
  - 将 `_reauth_json` 的 next 参数改为：优先 `request.META.HTTP_REFERER` 或当前 `request.get_full_path()`（同时做 allowed_host 校验），与 `_reauth_redirect` 保持一致策略。
- **回归用例建议**：
  - 对批量 API / 单条 API：触发 reauth_required 时，assert redirect 的 next 指向 referer。

### SEC-03（低/性能）导出接口的 `count()` 代价与策略不一致

- **位置**：团队审计导出 `team_audit_export` 现在计算 `queryset.count()` 用于写入 header/提示（[views.py:team_audit_export 附近](file:///Users/lingchong/Downloads/wwwroot/ToTP/totp/views.py)）
- **风险**：在数据量很大时，`count()` 会增加一次全量统计查询；若数据库缺少合适索引或过滤条件复杂，可能增加导出等待。
- **修复建议**：
  - 继续保留提示行（对可解释性有价值），但在极端场景可改为“超过阈值再 count”（例如先取 `export_limit+1` 条判断是否截断），或使用近似计数策略。

## 4. 权限与 RBAC 复核要点

### 4.1 当前模式

- 团队相关敏感页多采用 `_get_team_membership(require_manage=True)`，不满足直接 404（避免泄漏团队存在性）。
- 个人/团队空间共用部分入口（例如 list page space=team:*），通过 membership 计算 `can_manage`。

### 4.2 建议强化

- 对所有“写操作”视图（POST）保持 `@require_POST` + `@login_required` 一致；对 GET 导出加 `@never_cache`（目前已在多个导出中使用）。
- 对“片段接口”（tab fragment/panel）确保与页面入口一致的权限要求（目前已实现）。

## 5. 安全基线与工具接入建议

### 5.1 建议引入的工具

- Bandit（Python 安全扫描）
- Ruff（lint + 复杂度）
- djlint（Django 模板 lint）
- pip-audit（依赖漏洞扫描）

### 5.2 CI 建议（最小可用）

- PR 必须通过：
  - `python manage.py test`
  - `python -m compileall`
  - `ruff check .`（或 flake8）
  - `bandit -r . -x staticfiles,totp/migrations`

## 6. 高危漏洞与一键修复 Patch

- 本次审查范围内**未识别到明确高危漏洞**可直接“一键修复”且不引入产品行为破坏。
- 上述 SEC-01/SEC-02 属于中风险（配置/流程），建议纳入下一轮迭代按“先兼容、再收紧”的节奏落地。
