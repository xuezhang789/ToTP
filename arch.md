# 项目架构文档

## 1. 项目概述
本项目是一个基于 Django 的 TOTP（时间基一次性密码）管理系统，主要用于团队协作中的身份验证和权限管理。

## 2. 核心模块

### 2.1 数据模型 (`totp/models.py`)
- **Team**：团队模型，管理团队信息。
- **TeamMembership**：团队成员关系模型。
- **TeamInvitation**：团队邀请模型。
- **TOTPEntry**：TOTP 条目模型，存储一次性密码相关信息。
- **TOTPEntryAudit**：TOTP 条目审计日志模型。

### 2.2 视图逻辑 (`totp/views.py`)
- 处理用户请求，实现业务逻辑。

### 2.3 管理后台 (`totp/admin.py`)
- 配置 Django 管理后台，提供对数据模型的增删改查功能。

## 3. 功能模块

### 3.1 数据导入 (`totp/importers.py`)
- 提供数据导入功能，支持批量导入 TOTP 条目。

### 3.2 测试模块 (`totp/tests/`)
- 包含对各个功能的单元测试和集成测试。

## 4. 数据库迁移 (`totp/migrations/`)
- 记录数据模型的变更历史，支持数据库版本控制。

## 5. 项目配置 (`totp/apps.py`)
- 定义 Django 应用配置。

## 6. 交互关系
- 用户通过视图逻辑 (`views.py`) 与系统交互。
- 视图逻辑调用数据模型 (`models.py`) 进行数据操作。
- 管理后台 (`admin.py`) 提供管理员对数据的直接管理功能。

## 7. 架构图
```mermaid
graph TD
    A[用户] --> B[视图逻辑 (views.py)]
    B --> C[数据模型 (models.py)]
    C --> D[数据库]
    B --> E[管理后台 (admin.py)]
    E --> C
```

## 8. 后续优化建议
- 增加 API 文档，方便开发者集成。
- 优化数据导入性能，支持更大规模的数据处理。