---
feature_id: "FEAT-system-ca-by-algorithm"
rr_id: "30093768"
title: "系统预置CA证书按算法分组展示与证书库版本号"
date: "2026-11-13"
status: Draft
---
# Feature

> 模板定位：需求分析收敛产物。1 个 feature = 1 份跨多仓的完整需求，是拆解为各仓 proposal 的基础。
> 由 requirement/feasibility/decision 收敛而来。方案选型见 `03-arch-decision-record.md`。

## 1. 概述与价值

系统预置 CA 证书在"系统"Tab 按"国际算法/国密算法"分组展示并显示证书库版本号；海外设备无国密证书时不展示国密分组；SA `getSystemTrustedCertificateList` 新增可选 `certAlg` 按算法查询并返回 `certStoreInfo` 版本号。

| 字段 | 内容 |
|------|------|
| RR单号 | 30093768 |

## 2. 范围

### 目标
- 系统预置 CA 按"国际算法/国密算法"分组展示（FR-1）
- 每分组展示对应证书库版本号（FR-2）
- 海外设备（国密列表为空）不展示国密分组及版本号（FR-3）
- SA `getSystemTrustedCertificateList(certAlg?)` 按算法查询（FR-4）
- `CMResult.certStoreInfo` 返回 `certStoreVersion`/`smcertStoreVersion`（FR-5）
- 向后兼容：旧客户端不传 `certAlg` 行为不变（NFR-1）

### 非目标
- 用户 CA 列表、凭据列表展示不变
- 证书详情页内容不变
- D1 算法判定不升级（沿用当前 SM2 OID 匹配，R2 已知限制接受）
- NDK/ANI/CJ 多接口形态同步为后续工作（非本次交付）
- 不新增 IPC 消息码、不改动既有 `CmGetCertList` 接口

## 3. 成功标准（AC）

| AC# | 标准 | 可观察指标 | 验证方式 | FR |
|-----|------|-----------|---------|----|
| AC-1 | 系统 Tab 展示"国际算法"与"国密算法"两个分组 | 分组标题与各自证书条目 | 设备 UI 查看 / 客户端编译 | FR-1 |
| AC-2 | 每分组显示证书库版本号 | "证书库版本: x.x" 文本 | 设备 UI 查看 | FR-2 |
| AC-3 | 海外设备仅显示国际分组 | 国密分组不渲染 | 国密列表为空时 UI 验证 | FR-3 |
| AC-4 | `getSystemTrustedCertificateList(INTERNATIONAL)`/`(SM)` 分别返回对应算法证书 | 两列表互斥、并集=无参返回 | cm_sdk_test / SA 验证 | FR-4 |
| AC-5 | `CMResult.certStoreInfo` 含 `certStoreVersion`/`smcertStoreVersion` | 字段非空（国内） | NAPI 返回值校验 | FR-5 |
| AC-6 | 旧客户端不传 `certAlg` 返回全部系统 CA | 行为同原接口 | 向后兼容用例 | NFR-1 |

> 选定方案: D1-B + D2-A + D3-A + D4-A（参见 `03-arch-decision-record.md`）。

## 4. 受影响模块（跨仓）

| 领域 | 仓库 | 模块/路径 | 影响类型 | 兼容性策略 |
|------|------|-----------|---------|-----------|
| 客户端 App | applications_user_certificate_manager | `certmanager/.../pages/trustedCa.ets`（系统 Tab 渲染） | 需适配（改 ForEach 分组） | 运行时分支 |
| 客户端 App | applications_user_certificate_manager | `certmanager/.../presenter/CmShowSysCaPresenter.ets` | 需扩展（intl/sm 列表+版本+rebuild） | opt-in 新增 |
| 客户端 App | applications_user_certificate_manager | `certmanager/.../model/CertMangerModel.ets` + `@ohos.security.certManager.d.ts` | 需扩展（新接口+类型） | opt-in 新增 |
| SA | security_certificate_manager_SDD_user_certification | `interfaces/kits/napi/src/cm_napi_get_system_cert_list.cpp` | 需扩展（解析 certAlg+序列化 storeInfo） | opt-in 新增 |
| SA | security_certificate_manager_SDD_user_certification | `interfaces/innerkits/.../cert_manager_api.h/.c` + `cm_type.h` | 需扩展（新 innerkit+类型） | opt-in 新增 |
| SA | security_certificate_manager_SDD_user_certification | `frameworks/.../cm_ipc/src/cm_ipc_client.c` | 需扩展（新 client 函数） | opt-in 新增 |
| SA | security_certificate_manager_SDD_user_certification | `services/.../cm_ipc/cm_ipc_service.c` + `cm_ipc_service_cert_pack.c` | 需扩展（读 certAlg+pack storeInfo） | 运行时分支（可选 tag） |
| SA | security_certificate_manager_SDD_user_certification | `services/.../cert_manager_engine/main/core/src/cert_manager_query.c` | 需扩展（按 alg 过滤+版本号） | opt-in 新增 |

**模块覆盖检查结论**：pass（04 §4 与 02 §2.1 关键代码仓库分析表逐项对齐，无遗漏）。
**术语一致性检查结论**：pass（影响类型标签与 02 §2.1 一致，无漂移）。

## 5. 拆解指引

按仓拆分（R1 仓库隔离优先）：

| Proposal | 文件 | 边界/职责 | 估算工作量(人月) | Owner | 依赖 | GA 状态 |
|----------|------|----------|-----------------|-------|------|---------|
| P1 客户端 App | `05-proposal-client.md` | 系统 Tab 分组渲染 + 版本号展示 + 调用 SA 新 innerkit + d.ts 类型 | 0.4 | 客户端 App Owner | P2（SA 接口就绪） | 待 GA |
| P2 SA | `05-proposal-sa.md` | NAPI 解析 certAlg + innerkit/IPC 四件套 + engine 按 alg 过滤 + 版本号返回 | 1.1 | SA Owner | 无 | 待 GA |

**端到端总工作量**：0.4 + 1.1 = **1.5 人月**。
**复杂度**：1.5 < 5 → **简单**（满足简单≤5 人月上限）。
**拆分确认**：✅ 用户已于 2026-11-13 确认（按仓拆分 P1 客户端 + P2 SA）。

**FR→AC 追溯（Step 0.5.1）**：FR-1→AC-1；FR-2→AC-2；FR-3→AC-3；FR-4→AC-4；FR-5→AC-5；NFR-1→AC-6。编号一致，无遗漏。

## 6. 需求变更影响性分析

| 影响方 | 影响类型 | 说明 |
|--------|---------|------|
| 北向应用开发者 | 需适配（可选） | 新增可选 `certAlg` 参数与 `certStoreInfo` 字段；不传则行为不变（向后兼容） |
| 南向开发者 | 需适配 | SA innerkit 新增 `CmGetSystemTrustedCertList`、`CmCertAlgorithm`、`CmCertStoreInfo` |
| 分布式设备 | 无影响 | 不涉及跨设备场景 |
| 系统开发者（跨子系统） | 无影响 | 复用既有 IPC 消息码 `CM_MSG_GET_CERTIFICATE_LIST`，不新增消息码，不影响其它子系统 |
| 设备使用者 | 正向优化 | 系统证书 Tab 分类展示 + 版本号；海外设备不显示空国密分组，体验一致 |

## 7. 遗留问题闭环校验

`03-arch-decision-record.md §6`：评审会议认定无遗留问题 → 闭环校验通过，不阻断 Gate。

## 8. Review Ready Gate

- 模块覆盖：pass；术语一致：pass；AC↔FR 追溯：AC-1~6 映射 FR-1~5/NFR-1（无遗漏）；§6 闭环：通过（03 §6 无遗留）。
- 复杂度：简单（1.5 人月）；拆分已用户确认。
- **Gate 结论：Ready**（拆分确认后判定；注：因 `ohos-req-review-gate` subagent 未在本 session 加载，由主 Session 依据其规则判定，非独立 subagent）。
