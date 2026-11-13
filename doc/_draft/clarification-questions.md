# 澄清问题清单 — system-ca-by-algorithm

> 对应 `../01-requirement.md`。所有问题已回填 `**澄清结论**`。

## Q-1 RR单号 / 立项状态（P0）
需求是否已在 OHOS 电子流需求管理系统（iTop/RR）立项？若有 RR单号请提供；若为 SDD 练习需求无需立项，请确认"未立项"标注。

**澄清结论**：✅ 已立项，RR单号 `30093768`。已回填 frontmatter `rr_id` 与 §1 表格。

## Q-2 期望交付版本（P1）
本需求期望在哪个 OpenHarmony 版本交付？

**澄清结论**：✅ OpenHarmony 7.1 Release。已回填 frontmatter `expected_release` 与 §6。

## Q-3 接口响应时延基线（P2）
NFR-2 要求"不显著劣化"，需量化基线与目标值。

**澄清结论**：✅ 确认不设性能/功耗指标。理由：本需求为展示分类与接口可选参数扩展，不涉及性能功耗。已将 §6 性能/功耗预期调整为"不涉及，确认不设指标"，移除原 NFR-2。

## Q-4 证书库版本号来源（P1）
`certStoreVersion`/`smcertStoreVersion` 的版本号数据从哪里产生与维护？

**澄清结论**：⚠️ 条件待验证。版本号来源属技术实现决策，不纳入 requirement 正文（requirement 不含技术方案），由 `02-feasibility.md` 评估候选方案（镜像预置版本文件 / RDB / 其它），在 `03-arch-decision-record.md` 定稿。SA 侧当前实现的假设（读取 `/etc/security/certificates/cert_store_version`）仅作 feasibility 输入。

## Q-5 算法判定方式（P1）
SA 侧按 `certAlg` 过滤系统 CA 时，如何判定每个证书的算法？

**澄清结论**：⚠️ 条件待验证。算法判定属技术实现决策，不纳入 requirement 正文，由 `02-feasibility.md` / `03-arch-decision-record.md` 定。用户倾向：走 `cm_x509` 证书公钥解析（SM2/SM3 归国密，其余归国际）。SA 侧当前实现的 SM2 OID 字节匹配启发式作 feasibility 对比候选。

## Q-6 提出人/需求方（P2）
需求提出人具体身份（团队/角色）？

**澄清结论**：✅ 安全子系统证书管理。已回填 §1 提出人与 frontmatter `requester`。
