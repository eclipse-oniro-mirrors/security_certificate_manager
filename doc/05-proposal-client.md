---
target_release: "OpenHarmony 7.1 Release"
feature_id: "FEAT-system-ca-by-algorithm"
rr_id: "30093768"
issue: ""
author: "客户端 App Owner"
date: "2026-11-13"
status: GA-Approved
gate_a: "评审接纳(2026-11-13)"
---
# Proposal — P1 客户端 App

> 归档仓：applications_user_certificate_manager。过 GA（评审接纳）。

## 基本信息

| 字段 | 内容 |
|------|------|
| 需求ID | FEAT-system-ca-by-algorithm |
| RR单号 | 30093768 |

## 1. 背景与问题（Why）
系统预置 CA 引入国密算法后，当前客户端按单一平铺列表展示，无法区分国际/国密，且无证书库版本号。海外设备无国密证书却与国内同构展示。

## 2. 初始分级判断

| 判断项 | 结果 | 依据 |
|--------|------|------|
| 复杂度 | 简单 | 0.4 人月 |
| 涉及仓数量 | 1 | applications_user_certificate_manager |
| 是否涉及 Public/System API | 是（消费 SA 新 System API） | d.ts 扩展 |
| 是否涉及安全/性能关键路径 | 否 | 展示层 |
| 是否跨 SIG | 否 | 安全子系统内 |

## 3. 目标 / 非目标
### 目标
- 系统 Tab 按国际/国密分组展示（FR-1）
- 每分组显示证书库版本号（FR-2）
- 海外设备不展示国密分组（FR-3）
- 调用 SA 新 innerkit 按算法查询（FR-4/FR-5 消费侧）

### 非目标
- 用户 CA/凭据列表不变；详情页不变；不改 SA 侧实现。

## 4. 用户故事与能力

| US# | As a... I want... so that... | AC |
|-----|------------------------------|----|
| US-1 | 最终用户，我想看到系统 CA 按算法分类 | AC-1 |
| US-2 | 最终用户，我想看到证书库版本号 | AC-2 |
| US-3 | 海外用户，我不想看到空的国密分组 | AC-3 |

## 5. 成功标准

| 标准 | 可观察指标 | 验证方式 |
|------|-----------|---------|
| 分组展示 | 两个分组标题+条目 | UI 查看 / hvigor 编译 |
| 版本号 | "证书库版本: x.x" | UI 查看 |
| 海外不展示国密 | 国密段不渲染 | 国密列表空时验证 |

## 6. 影响范围

| 子系统 | 仓库 | 模块/路径 | 影响类型 |
|--------|------|-----------|---------|
| 安全 | applications_user_certificate_manager | `certmanager/.../pages/trustedCa.ets`、`presenter/CmShowSysCaPresenter.ets`、`model/CertMangerModel.ets`、`@ohos.security.certManager.d.ts` | 需适配/需扩展 |

## 7. 假设与开放问题
### 假设
- SA 侧 `getSystemTrustedCertificateList(certAlg)` 与 `certStoreInfo` 已就绪（P2 提供）。
### 开放问题
- 无（依赖 P2 接口就绪）。

## 8. 不涉及项确认（8 维）

| 维度 | 是否涉及 | 依据 |
|------|---------|------|
| 性能 | 否 | 不涉及性能功耗 |
| 安全/权限 | 否 | 沿用既有权限 |
| 兼容性 | 是 | 向后兼容旧调用 |
| API/SDK | 是 | 消费新 System API |
| IPC/跨进程 | 否 | IPC 在 SA 侧 |
| 构建/组件 | 否 | 无构建变更 |
| 国际化/无障碍 | 否 | 沿用既有 |
| 数据迁移 | 否 | 无 |
