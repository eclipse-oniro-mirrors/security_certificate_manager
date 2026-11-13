# Feasibility 澄清问题清单 — system-ca-by-algorithm

> 对应 `../02-feasibility.md`。所有问题已回填 `**澄清结论**`。
> 注：选型决策属 `03-arch-decision-record.md`，本清单只关闭分析完整性/证据缺口。

## FQ-1 候选方案完整性（P1）
D1/D2/D3/D4 候选路径是否完整？

**澄清结论**：✅ 候选完整。D1（cm_x509 / SM2 OID / 目录约定）、D2（版本文件 / RDB / 编译宏）、D3（复用消息+可选tag / 新增消息码）、D4（单List ForEach / 双List / LazyForEach）四个决策点候选路径无遗漏。

## FQ-2 SA 侧编译验证计划（P0，对应 R1）
SA 未本地编译，验证如何安排？

**澄清结论**：✅ 计划在 OH 源码树验证。`./build.sh --product-name <product> --build-target certmanager / cert_manager_service` + `cm_sdk_test --gtest_filter=CmGetCertListTest.*`。Owner 与具体时点待 Phase 1 规划补齐。R1 由"高"降为"中（有验证计划，待执行）"。

## FQ-3 竞品参考缺失（P2）
是否接受无竞品参考？

**澄清结论**：✅ 用户确认接受"无竞品参考，不作为可行性判断依据"。本需求为系统能力增强，竞品参考 N/A。

## FQ-4 工作量估算基准（P2）
500行≈1人月 + 系数是否认可？

**澄清结论**：✅ 认可。统一标准 500行≈1人月，测试×0.3、设计×0.1、UX×0.1；当前实现端到端约 1.5 人月合理。
