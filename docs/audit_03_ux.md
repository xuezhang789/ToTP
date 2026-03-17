# UX 走查与优化方案

## 0. 总览

项目采用 Bootstrap 5 + Django 模板为主，交互增强由原生 JS 负责（`static/js/ui.js` 作为基础能力：toast、confirm、copy、form invalid focus）。

走查重点：

- 交互一致性：按钮/弹窗/禁用/Loading/错误提示
- 可访问性：键盘可达性、ARIA、对比度与缩放
- 性能体验：避免整页刷新、减少阻塞请求、长列表与导出体验
- 多端：移动端布局与“同等能力”补齐

## 1. 交互一致性（现状与建议）

### 1.1 现有交互基座

- toast/inline alert：`window.appToast`、`window.appNotify`（[ui.js](file:///Users/lingchong/Downloads/wwwroot/ToTP/static/js/ui.js)）
- confirm：`window.appConfirm`（同上）
- copy：`window.appCopyToClipboard`
- button loading：`window.appSetButtonLoading`

建议统一规则：

- “提交类”交互：优先使用 `appSetButtonLoading`，禁用按钮并显示 loading label。
- “不可见错误”：toast；“可见表单错误”：inline alert + focus invalid。
- “敏感操作”：必须 confirm（含 hint），并确保 `aria-live` 提示。

### 1.2 关键页面建议

- 密钥列表（`list.html`）：
  - 建议：进一步统一所有 modal 的“提交按钮 loading + 防重复提交”模式（大部分已做）。
  - 可选：对局部刷新增加“顶部小提示：已更新列表”。
- 团队工作台（`team_home.html`）：
  - 建议：tab 延迟加载要有 skeleton 或更明确的 loading 状态（避免空白）。
- 团队审计（`team_audit.html`）与一次性链接审计（`one_time_links.html`）：
  - 建议：筛选条件以 chip 展示（已补齐），并提供“清除全部”。
  - 建议：导出按钮在导出上限/截断时给更明确提示（已补齐 team_audit；一次性链接导出目前无截断提示，可选补齐）。

## 2. 可访问性（A11y）

### 2.1 已具备能力

- toast container + live region：`#appToastContainer`、`#appLiveRegion`
- 多数按钮具备 `aria-label`（列表行按钮等）

### 2.2 走查问题类型（建议长期 checklist）

- **键盘可达性**
  - modal 打开时 focus 应落在第一可输入控件（部分 modal 已使用 `data-autofocus`，建议形成统一 hook）
  - 表格行内 icon-only 按钮必须有 `aria-label`
- **表单语义**
  - label 必须绑定 `for/id`（团队审计已补齐；其它筛选区建议统一）
  - `role="search"` 与 `aria-label` 用于筛选表单（审计页已补齐）
- **视觉对比**
  - badge/浅色提示在暗色模式/低对比度场景需要复核（目前未见暗色主题切换）。

## 3. 性能体验（SSR + 原生 JS）

### 3.1 建议策略

- “可局部刷新”的页面，不做整页 reload：
  - 密钥列表：已支持局部刷新 tbody + pagination（用于生成一次性链接后的刷新）
  - 一次性链接审计：批量操作目前整页 reload，可选改为“就地更新 status badge + 失效按钮禁用”（需维护更多状态）
- 频繁更新的区域（TOTP 倒计时）：
  - 现已用 ticker + pause/resume（`totp_list.js`），建议保持“页面隐藏暂停”策略。

### 3.2 前端错误兜底

- 网络失败：toast + 保持按钮可重试（现有大部分 fetch 都符合）
- 服务器 403 reauth_required：统一走 reauth（现有已实现）

## 4. 多端一致性（移动端）

### 4.1 已补齐的模式

- 审计页移动端采用卡片/列表（`d-md-none`）+ 桌面表格（`d-none d-md-block`）。

### 4.2 建议重点

- “能力等价”：桌面端的全选/批量能力必须在移动端有等价入口（一次性链接审计已补齐移动端全选；其它列表类可按此模式推广）。

## 5. 可落地的改动点清单（按优先级）

### P0（稳定性与可用性）

- 所有筛选表单统一 label 绑定、role=search、回车提交行为一致化。
- 批量操作统一在 confirm 文案中提示“本次仅作用于仍可用/可处理项”的数量。

### P1（效率）

- 重要审计/列表页新增更多快捷筛选（例如“即将过期”“剩余次数=1”）。
- 批量后就地更新（减少 reload）：
  - 代价：需要维护每条记录 status、按钮状态与 chip 计数。

### P2（工程化）

- 引入 e2e（Playwright/Selenium）覆盖关键交互（登录、生成一次性链接弹窗、批量失效、团队审计筛选/导出等）。
