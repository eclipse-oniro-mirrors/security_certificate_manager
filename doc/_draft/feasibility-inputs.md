# Feasibility 输入资料记录 — system-ca-by-algorithm

> Step 0.1.8 产出。记录用户提供的本地关键代码仓路径、接口文档、Owner 结论、前置依赖资料，或用户确认不额外提供。

## 用户提供资料

代码仓（已克隆到本地，主 Session 可直接 Read/grep，源码级场景）：

| 仓 | 本地路径 | 角色 |
|----|----------|------|
| applications_user_certificate_manager | `D:\s30080125\SDD\user_certification_manager\repo` | 客户端 App（系统证书列表 UI、Presenter、Model） |
| security_certificate_manager_SDD_user_certification | `D:\s30080125\SDD\sa_sdd_user_certification` | SA（NAPI/innerkit/IPC/engine） |

## 代码预检（Step 0.1.9，主 Session 已执行）

关键词：`getSystemTrustedCertificateList`、`CmGetCertList`、`trustedCa`、`CertAlgorithm`。
命中（top，已用于 §2.1 代码证据）：
- 客户端：`certmanager/src/main/ets/pages/trustedCa.ets`、`presenter/CmShowSysCaPresenter.ets`、`model/CertMangerModel.ets`、`@ohos.security.certManager.d.ts`
- SA：`interfaces/kits/napi/src/cm_napi_get_system_cert_list.cpp`、`interfaces/innerkits/.../cert_manager_api.h/.c`、`frameworks/.../cm_ipc/src/cm_ipc_client.c`、`services/.../cm_ipc/cm_ipc_service.c`、`services/.../cm_ipc/cm_ipc_service_cert_pack.c`、`services/.../cert_manager_engine/main/core/src/cert_manager_query.c`、`frameworks/.../include/cert_manager_service_ipc_interface_code.h`

## 其它

- 无 Owner 结论 / 竞品 PoC / 接口文档额外提供。
- 证据免责声明：本需求代码已实现并在客户端侧通过 hvigor 编译验证；SA 侧为 OpenHarmony 系统组件，未在本地构建（无 OH 源码树），SA 侧代码证据为源码级阅读，未编译验证。
