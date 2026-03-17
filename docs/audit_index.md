# 项目全量审查交付索引

本索引对应一次“可复用”的源码审查交付物集合，覆盖：模块梳理与架构、缺陷与安全审计、UX 走查、功能建议与 PRD。

## 交付物

- ① 《功能模块清单与架构文档》：见 [audit_01_modules.md](./audit_01_modules.md)
- ② 《缺陷与安全审计报告》：见 [audit_02_security.md](./audit_02_security.md)
- ③ 《UX 走查与优化方案》：见 [audit_03_ux.md](./audit_03_ux.md)
- ④ 《实用功能建议与 PRD 合集》：见 [audit_04_prds.md](./audit_04_prds.md)

## 范围说明

- 覆盖目录：`project/`、`accounts/`、`totp/`、`templates/`、`static/`、`docs/`（不包含 `staticfiles/` 与虚拟环境目录）。
- 代码规模（不含 migrations/staticfiles/.venv）：后端（Python）与模板、少量原生 JS/CSS，Django 单体应用。
  - totp：44 文件 / 7640 行
  - templates：30 文件 / 6216 行
  - static：7 文件 / 4345 行
  - accounts：14 文件 / 919 行
  - project：7 文件 / 237 行

## 约束与方法

- 本仓库未内置 SonarQube/ESLint/Bandit/SpotBugs 等全套扫描配置；审计报告中给出可落地的接入方案与建议规则集。
- UML/架构图采用 Markdown + Mermaid（可直接在 GitHub/GitLab 或支持 Mermaid 的 Markdown 渲染器查看）。
