---
feature_id: "FEAT-system-ca-by-algorithm"
rr_id: "30093768"
ir_id: "IR-system-ca-by-algorithm"
generated_by: skill-feat-to-ir（手工对齐）
date: "2026-11-13"
status: Baseline
---
# Initial Requirement

> 由 04-feature.md 收敛生成。RR单号从 04-feature.md 继承。

## 0. 需求追踪

| 字段 | 内容 |
|------|------|
| RR单号 | 30093768 |
| Feature ID | FEAT-system-ca-by-algorithm |
| IR ID | IR-system-ca-by-algorithm |

## 1. 需求价值
系统预置 CA 证书按国际/国密算法分组展示并显示证书库版本号，提升国密算法引入后的可识别性与版本可追溯性；海外设备无国密时不展示国密分组，体验一致。

## 2. 详细描述
系统证书"系统"Tab 按"国际算法/国密算法"分组展示系统预置 CA，每分组显示证书库版本号。SA `getSystemTrustedCertificateList` 新增可选 `certAlg` 按算法查询，`CMResult` 新增 `certStoreInfo`（`certStoreVersion`/`smcertStoreVersion`）。海外设备国密列表为空时不展示国密分组。向后兼容旧客户端。

## 3. 验收目标
AC-1~AC-6（见 04-feature.md §3）：分组展示、版本号、海外不展示国密、按算法查询、certStoreInfo、向后兼容。

## 4. 验收平台
OpenHarmony 设备（手机/平板/PC/2in1 等），国内设备（含国密）与海外设备（无国密）均覆盖。

## 5. RR编号
30093768

## 6. 适用产品差异分析
| 设备形态 | 差异 |
|----------|------|
| 国内设备 | 展示国际+国密两个分组与版本号 |
| 海外设备 | 仅展示国际分组（国密列表为空，不展示国密分组与版本号） |

## 7. 适用OS规格
OpenHarmony 7.1 Release（API Level 对应 7.1）。

## 8. 是否涉及性能和功耗
否。本需求为展示分类与接口可选参数扩展，不涉及性能功耗（确认不设指标）。

## 9. 是否涉及UX
是。系统证书列表分组标题（"国际算法"/"国密算法"）与版本号信息行展示。

## 10. 是否涉及资料新增和变更
是。`@ohos.security.certManager.d.ts` 声明变更（`getSystemTrustedCertificateList(certAlg?)`、`CMResult.certStoreInfo`、`CertStoreInfo`）；SDK 文档需同步（注：d.ts 在 interface_sdk-js 仓，需跨仓协同）。

## 11 是否涉及API
是。System API：`getSystemTrustedCertificateList` 新增可选参数；`CMResult` 新增可选字段。向后兼容（可选）。

## 12. 依赖子系统领域
安全子系统（证书管理 SA 3512）；客户端证书管理应用。

## 13. 是否需要开发Sample
否。

## Proposal 拆解

| Proposal | 仓 | 边界 | 工作量(人月) | GA |
|---|---|---|---|---|
| P1 客户端 App | applications_user_certificate_manager | UI 分组+版本号+调 SA 新 innerkit | 0.4 | GA-Approved |
| P2 SA | security_certificate_manager_SDD_user_certification | NAPI+innerkit+IPC+engine 按算法过滤+版本号 | 1.1 | GA-Approved |
