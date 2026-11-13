---
feature_id: "FEAT-system-ca-by-algorithm"
rr_id: "30093768"
generated_by: "ohos-req-intake-orchestration（手工对齐）"
date: "2026-11-13"
status: Ready
---

# Handoff 契约 — Phase 0 → Phase 1-9 交接

> Phase 0 到 Phase 1-9 的唯一交接点。

## Phase 0 完成状态

| 检查项 | 状态 | 路径 |
|--------|------|------|
| 01-requirement.md status=Clarified | ✅ | doc/01-requirement.md |
| 02-feasibility.md status=Clarified | ✅ | doc/02-feasibility.md |
| 03-arch-decision-record.md status=Accepted | ✅ | doc/03-arch-decision-record.md |
| 04-feature.md Gate=Ready | ✅ | doc/04-feature.md |
| 拆分结果已用户确认 | ✅ | 04-feature.md §5 |
| IR.md 存在 | ✅ | doc/IR.md |
| proposal 文件存在 | ✅ | doc/05-proposal-client.md, doc/05-proposal-sa.md |
| SR 文件存在（GA-Approved 后） | ✅ | doc/SR-01.md, doc/SR-02.md |

## Gate 状态

| 字段 | 值 |
|------|-----|
| Gate 结论 | Ready |
| 评审决策状态 | Accepted（用户接纳 2026-11-13） |
| ADR 状态 | Accepted |
| IR 状态 | Baseline |
| 条件项 | 无 |

## Phase 0 产物路径

| 产物 | 路径 |
|------|------|
| requirement | doc/01-requirement.md |
| feasibility | doc/02-feasibility.md |
| decision | doc/03-arch-decision-record.md |
| feature | doc/04-feature.md |
| IR | doc/IR.md |
| SR | doc/SR-01.md（客户端）, doc/SR-02.md（SA） |

## 关键决策摘要

| 决策 | 结论 | 来源 |
|------|------|------|
| RR单号 | 30093768 | 01-requirement.md |
| 选定方案 | D1-B(SM2 OID)+D2-A(版本文件)+D3-A(复用消息+tag)+D4-A(单List ForEach) | 03-arch-decision-record.md §5 |
| Gate 结论 | Ready | 04-feature.md §8 |
| 拆分方式 | 按仓（P1 客户端 + P2 SA） | 04-feature.md §5 |
| 评审决策 | 接纳 | Step 0.6 |

## Proposal 清单

| Proposal | 文件 | 拆分方式 | 估算工作量 | Owner | GA 状态 | SR 文件 |
|----------|------|----------|-----------|-------|---------|---------|
| P1 客户端 App | 05-proposal-client.md | 按仓 | 0.4 人月 | 客户端 App Owner | GA-Approved | SR-01.md |
| P2 SA | 05-proposal-sa.md | 按仓 | 1.1 人月 | SA Owner | GA-Approved | SR-02.md |

> 端到端总工作量 1.5 人月（简单）。

## 关键代码路径（来自 02 §2.1，供 Phase 1-9 验证）

- 客户端：`trustedCa.ets`、`CmShowSysCaPresenter.ets`、`CertMangerModel.ets`、`@ohos.security.certManager.d.ts`（仓 applications_user_certificate_manager）
- SA：`cm_napi_get_system_cert_list.cpp`、`cert_manager_api.h/.c`、`cm_type.h`、`cm_ipc_client.c`、`cm_ipc_service.c`、`cm_ipc_service_cert_pack.c`、`cert_manager_query.c`（仓 security_certificate_manager_SDD_user_certification）

## 实现现状

两侧代码均已实现（决策与当前实现一致，无需方案级改动）：
- 客户端：`hvigorw assembleHap` 编译 0 error（DevEco 5.0.3 / API 12）。
- SA：源码级完整，未本地编译（无 OH 源码树），待 Phase 1 在 OH 源码树 `./build.sh --build-target certmanager/cert_manager_service` + `cm_sdk_test` 验证（R1）。
- 已知风险：R2（D1-B SM2 OID 启发式对 PEM 可能漏判）已接受；R3（版本文件预置维护流程）待镜像构建侧确认。

## Phase 1-9 启动前置检查

- [x] handoff.md 存在且可读取
- [x] IR.md 存在
- [x] 04-feature.md Gate=Ready
- [x] 拆分结果已用户确认
- [x] 03-arch-decision-record.md status=Accepted
- [x] 03 §6 遗留问题由用户评审会议输入（认定无遗留）
- [x] 03 §6 遗留项三字段齐全（无遗留项，N/A）
- [x] 每个 proposal 工作量 ≤5 人月（0.4 / 1.1）
- [x] 至少一个 proposal 存在
- [x] GA-Approved proposal 均有对应 SR（P1→SR-01, P2→SR-02）
- [x] 每个 SR §二 责任人表 分析责任人/SE/TSE/测试责任人 已指定（非"待确定"）

## 交接说明

- Phase 1-9 以 `05-proposal-client.md` / `05-proposal-sa.md` 为入口，IR 与 feature 作参考上下文。
- Phase 0 产物（01-04/IR/SR）在 Phase 1-9 中引用不修改。
- 客户端侧代码已实现并编译通过；SA 侧代码已实现待 OH 源码树构建验证。

## 状态流转

handoff.md status = **Ready**：Phase 0 完成，所有前置检查通过，可启动 ohos-delivery 进入 Phase 1-9。
