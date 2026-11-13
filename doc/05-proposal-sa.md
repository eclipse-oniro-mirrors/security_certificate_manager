---
target_release: "OpenHarmony 7.1 Release"
feature_id: "FEAT-system-ca-by-algorithm"
rr_id: "30093768"
issue: ""
author: "SA Owner"
date: "2026-11-13"
status: GA-Approved
gate_a: "评审接纳(2026-11-13)"
---
# Proposal — P2 SA

> 归档仓：security_certificate_manager_SDD_user_certification。过 GA（评审接纳）。

## 基本信息

| 字段 | 内容 |
|------|------|
| 需求ID | FEAT-system-ca-by-algorithm |
| RR单号 | 30093768 |

## 1. 背景与问题（Why）
客户端按算法分组展示依赖 SA 提供按算法过滤的证书列表与证书库版本号。当前 SA `getSystemTrustedCertificateList` 不支持 `certAlg` 参数，`CMResult` 不含版本号字段。

## 2. 初始分级判断

| 判断项 | 结果 | 依据 |
|--------|------|------|
| 复杂度 | 简单 | 1.1 人月 |
| 涉及仓数量 | 1 | security_certificate_manager_SDD_user_certification |
| 是否涉及 Public/System API | 是（System API 扩展） | innerkit+NAPI |
| 是否涉及安全/性能关键路径 | 否 | 查询接口，非密钥路径 |
| 是否跨 SIG | 否 | 安全子系统内 |

## 3. 目标 / 非目标
### 目标
- NAPI `getSystemTrustedCertificateList(certAlg?)` 解析可选参数（FR-4）
- `CMResult.certStoreInfo` 返回版本号（FR-5）
- innerkit+IPC 四件套按算法过滤+版本号返回
- 向后兼容旧客户端（NFR-1）

### 非目标
- 不新增 IPC 消息码（复用 CM_MSG_GET_CERTIFICATE_LIST + 可选 tag）
- 不升级 D1 算法判定（沿用 SM2 OID 匹配，R2 接受）
- NDK/ANI/CJ 多形态同步为后续工作

## 4. 用户故事与能力

| US# | As a... I want... so that... | AC |
|-----|------------------------------|----|
| US-4 | 应用开发者，我想按算法查询系统 CA | AC-4 |
| US-5 | 应用开发者，我想获取证书库版本号 | AC-5 |
| US-6 | 旧客户端，我不传 certAlg 时行为不变 | AC-6 |

## 5. 成功标准

| 标准 | 可观察指标 | 验证方式 |
|------|-----------|---------|
| 按算法查询 | intl/sm 列表互斥、并集=全部 | cm_sdk_test |
| 版本号返回 | certStoreInfo 字段非空 | NAPI 返回值校验 |
| 向后兼容 | 旧客户端返回全部 | 兼容用例 |

## 6. 影响范围

| 子系统 | 仓库 | 模块/路径 | 影响类型 |
|--------|------|-----------|---------|
| 安全 | security_certificate_manager_SDD_user_certification | `interfaces/kits/napi/src/cm_napi_get_system_cert_list.cpp`、`interfaces/innerkits/.../cert_manager_api.h/.c`+`cm_type.h`、`frameworks/.../cm_ipc/src/cm_ipc_client.c`、`services/.../cm_ipc/cm_ipc_service.c`+`cm_ipc_service_cert_pack.c`、`services/.../cert_manager_engine/main/core/src/cert_manager_query.c` | 需扩展 |

## 7. 假设与开放问题
### 假设
- 版本号来源 D2-A：镜像预置 `/etc/security/certificates/cert_store_version`（需镜像构建侧预置）。
- 算法判定 D1-B：SM2 OID 字节匹配（R2 已知限制接受）。
### 开放问题
- 版本文件预置与维护流程需镜像构建侧确认（R3，非阻塞）。

## 8. 不涉及项确认（8 维）

| 维度 | 是否涉及 | 依据 |
|------|---------|------|
| 性能 | 否 | 不涉及性能功耗 |
| 安全/权限 | 是 | IPC 服务端沿用 CmContext 校验，不新增越权路径 |
| 兼容性 | 是 | 可选 tag + 尾部字节，向后兼容 |
| API/SDK | 是 | System API 扩展 |
| IPC/跨进程 | 是 | 复用消息码 + 可选 tag |
| 构建/组件 | 否 | 无构建变更 |
| 国际化/无障碍 | 否 | 无 |
| 数据迁移 | 否 | 无 |
