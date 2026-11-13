---
feature_id: "system-ca-by-algorithm"
rr_id: "30093768"   # 已立项，RR单号
requester: "安全子系统证书管理"
date: "2026-11-13"
status: Clarified
expected_release: "OpenHarmony 7.1 Release"
---
# 原始诉求

> 模板定位：记录需求提出者的原始诉求，原味留存，不做修饰。对应生命周期「需求分析」起点。
> 填写引导见各章节注释，**标 🔖 的章节为必填**，其余为可选（无内容可写"无"或整节省略）。

## 1. 来源与背景 🔖

| 字段 | 内容 |
|------|------|
| 提出人 | 安全子系统证书管理 |
| RR单号 | 30093768（已立项） |
| 来源类型 | 规划/产品需求（国密算法证书库引入后的配套展示诉求） |
| 触发场景 | 系统预置 CA 证书库同时包含国际算法与国密算法证书后，用户在"设置 > 隐私 > 证书与凭据 > 系统"查看系统 CA 时无法区分两类算法，且无法获知证书库版本 |
| 关联Issue | 无 |

## 2. 诉求原文 🔖

以下为需求方原始描述，原味留存（含其给出的接口契约原文，技术细节由下游 feasibility/arch-decision 处理）：

> 证书管理应用在展示系统预置 CA 证书时，按照国际算法和国密算法分开展示，同时增加对应的证书库版本号的信息显示，海外的设备没有预置国密算法的 CA 证书，不需要展示国密算法证书库版本号及证书列表（通过查询系统预置 CA 证书列表是否为空进行判断），需要调用证书管理 SA 提供的 getSystemTrustedCertificateList 接口，新增可选参数支持查询指定算法的证书跟列表。
>
> function getSystemTrustedCertificateList(certAlg?:CertAlgorithm):Promise<CMResult>;
>
> CMResult 新增可选字段，返回根证书库可选版本号
> export interface CMResult{ certStoreInfo?:CertStoreInfo; }
> export interface CertStoreInfo { certStoreVersion:string //国际算法CA证书库版本号 smcertStoreVersion:string //国密算法CA证书库版本号 }

## 3. 用户痛点与业务场景 🔖

| 用户类型 | 当前痛点 | 当前行为 | 影响 |
|----------|----------|----------|------|
| 最终用户 | 系统预置 CA 证书按单一平铺列表展示，国际算法与国密算法证书混排，无法区分 | 进入"系统"证书 Tab 看到全部系统 CA 混在一起 | 无法识别哪些是国密算法证书、哪些是国际算法证书；无法获知证书库版本 |
| 最终用户（海外设备） | 海外设备未预置国密算法 CA 证书，但当前实现未据此隐藏国密相关展示 | 与国内设备同构展示 | 在无国密证书的设备上出现冗余/空国密分组，体验不一致 |

业务背景：随着国密算法（SM2/SM3/SM4）证书库在系统预置 CA 中引入，系统 CA 同时包含国际算法与国密算法两类。需要在 UI 上分类展示并显示各自证书库版本号，便于用户识别与运维定位；海外设备无国密证书，不应展示国密分组。

## 4. 期望 🔖

- 系统预置 CA 证书在"系统"Tab 按"国际算法"与"国密算法"分两个分组展示。
- 每个分组展示对应的证书库版本号。
- 海外设备（国密证书列表为空）不展示国密算法分组及版本号——通过查询系统预置 CA 证书列表是否为空进行判断。
- 证书管理 SA 的 `getSystemTrustedCertificateList` 接口新增可选参数，支持按指定算法查询根证书列表；`CMResult` 新增可选字段返回根证书库版本号。

---

以下章节为**可选**，按需填写：

## 5. 适用设备/产品形态

| 设备/产品 | 定位 | 说明 |
|----------|------|------|
| 通用（手机/平板/PC/2in1 等） | 主要目标 | 国内设备预置国际+国密 CA；海外设备仅预置国际 CA |

## 6. 约束与期望

| 类别 | 内容 |
|------|------|
| 已知约束 | 海外设备未预置国密算法 CA 证书；海外判断依据为"查询系统预置 CA 证书列表是否为空" |
| 期望交付版本 | OpenHarmony 7.1 Release |
| 性能/功耗预期 | 不涉及，确认不设指标（理由：本需求为展示分类与接口可选参数扩展，不涉及性能功耗） |

**功能需求（FR）：**

| 编号 | 描述 | 优先级 | 来源依据 |
|------|------|--------|----------|
| FR-1 | 系统预置 CA 按"国际算法/国密算法"分组展示 | P0 | 诉求原文 §2 |
| FR-2 | 每个分组展示对应证书库版本号（国际版本号、国密版本号） | P1 | 诉求原文 §2 |
| FR-3 | 海外设备（国密列表为空）不展示国密分组及版本号 | P0 | 诉求原文 §2 |
| FR-4 | SA `getSystemTrustedCertificateList` 新增可选 `certAlg` 参数，按算法查询根证书列表 | P0 | 诉求原文 §2 |
| FR-5 | `CMResult` 新增可选 `certStoreInfo`，含 `certStoreVersion` 与 `smcertStoreVersion` | P0 | 诉求原文 §2 |

> 优先级依据：P0 = 客户端分组展示与 SA 按算法查询/版本号返回的核心能力，缺则需求不成立；P1 = 配套版本号展示，可分阶段交付。

**非功能需求（NFR）：**

| 编号 | 描述 | 基线 | 目标值 |
|------|------|------|--------|
| NFR-1 | 向后兼容：旧客户端不传 `certAlg` 时行为与原接口一致 | 原 `getSystemTrustedCertificateList()` 行为 | 行为不变，返回全部系统 CA |

> 性能/功耗：本需求不涉及，确认不设指标（理由见上表"性能/功耗预期"）。
> 技术实现项（证书库版本号来源、算法判定方式）不纳入 requirement，由 `02-feasibility.md` / `03-arch-decision-record.md` 决策（见 `_draft/clarification-questions.md` Q-4/Q-5）。

## 7. 业界竞品参考

无。

## 8. 是否涉及 UX 设计

是。涉及系统证书列表页的分组标题（"国际算法"/"国密算法"）与版本号信息行的展示交互；视觉/交互细节由下游 UX 评估。

## 9. 附件与证据

| 类型 | 链接/路径 | 说明 |
|------|-----------|------|
| 客户端仓 | applications_user_certificate_manager（gitcode: sunzibin001/applications_user_certificate_manager） | 系统证书列表 UI、CmShowSysCaPresenter、trustedCa.ets |
| SA 仓 | security_certificate_manager_SDD_user_certification（gitcode: sunzibin001/security_certificate_manager_SDD_user_certification） | getSystemTrustedCertificateList NAPI/innerkit/IPC/engine 实现 |
| 客户端 spec（自由格式，待按本模板归档） | user_certification_manager/repo/doc/SDD_system_ca_algorithm_grouping.md | 客户端侧已实现的设计记录 |
| SA spec（自由格式，待按本模板归档） | sa_sdd_user_certification/doc/SDD_sa_system_cert_list_by_algorithm.md | SA 侧已实现的设计记录 |
