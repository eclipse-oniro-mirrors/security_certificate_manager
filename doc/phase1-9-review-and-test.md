# Phase 1-9 评审与测试报告 — system-ca-by-algorithm

> 对已实现代码（客户端 + SA）执行 4 项 Phase 1-9 活动：安全/代码评审（ohos-dev-security-code-review + cpp-coding-style）、API 评审（c-api-review + arkts-api-review）、单元测试规划（ohos-test-ut-generation）、Fuzz 规划（ohos-test-fuzz-generation）。
> skill 工具未注册，按各 SKILL.md 规则手工执行。

## 1. 安全/代码评审（ohos-dev-security-code-review）

### 评审路由
入口点：SA IPC stub `CmIpcServiceGetCertificateList`（cm_ipc_service.c:81）。攻击者可控数据：客户端经 CmParamSet 传入的 `store`、`certAlg`（CM_TAG_PARAM1_UINT32）。汇：engine 证书枚举/过滤、版本文件读取、outData 打包。

### 发现

**[MEDIUM SECURITY RISK] 输入校验 — certAlg 未在 stub 边界校验**

- Location: `services/.../cm_ipc/cm_ipc_service.c` `CmIpcServiceGetCertificateList`
- Issue: stub 经 `CmGetParam(paramSet, CM_TAG_PARAM1_UINT32, &algParam)` 读取 certAlg 后，未校验其 ∈ {CM_CERT_ALG_ALL(0), INTERNATIONAL(1), SM(2)} 即 `(enum CmCertAlgorithm)certAlg` 传入 engine。innerkit `CmGetSystemTrustedCertList` 有校验，但恶意 IPC 客户端可绕过 innerkit 直连 stub 发送越界值（如 99）。
- 现状影响：engine `CmGetSystemTrustedCertListInfo` 对 `certAlg != ALL` 时 `alg != certAlg` 恒真 → 全部证书被过滤 → 返回空列表。**fail-safe（无崩溃、无越权、无信息泄漏）**，但属边界缺校验。
- Required fix（如需加固）：
  ```c
  if (algParam != NULL) {
      uint32_t v = algParam->uint32Param;
      if (v > CM_CERT_ALG_SM) { CM_LOG_E("invalid certAlg %u", v); ret = CMR_ERROR_INVALID_ARGUMENT; break; }
      certAlg = (enum CmCertAlgorithm)v;
  }
  ```
- Impact：低（当前 fail-safe）；加边界校验为纵深防御。

**其余安全项（通过）**：
- 身份/权限：stub 沿用 `GetInputParams` 构造 `CmContext` + `CmServiceGetSystemCertListCheck(store)`，未新增越权路径。
- 内存：`CmMalloc/CmFree` + `memset_s`/`memcpy_s`（版本号、certBlob）；NAPI 侧 `CmCertStoreInfo` 在 `DeleteGetCertListAsyncContext` 释放（前序内存泄漏复查已确认无泄漏）。
- 隐私日志：仅日志打印 certAlg（数值）与版本号（公开元数据），无私钥/口令/PII。
- 兼容：可选 tag + 响应尾部追加，旧客户端 `CmCertificateListUnpackFromService` 不校验总长，不受影响。

### C++ 风格（ohos-dev-cpp-coding-style 简评）
- SA 新增代码遵循既有命名（PascalCase + 分层前缀 `Cm*`/`CmIpcService*`）、`CM_LOG_*`、`CmMalloc/CmFree`、4 空格缩进、Apache-2.0 头。
- `cert_manager_query.c` 新增 `GetSystemCertAlgorithm`/`ReadCertStoreVersion` 使用 `fopen/fread/fgets/memcmp/strnlen`（已补 `#include <stdio.h>/<string.h>`）；生产建议改用仓内文件读取封装以统一风格（非阻塞）。

## 2. API 评审（ohos-design-c-api-review + arkts-api-review）

### SA innerkit C API（cert_manager_api.h / cm_type.h）
| 规则 | 结果 | 说明 |
|---|---|---|
| 命名 PascalCase 动宾 | ✅ | `CmGetSystemTrustedCertList` |
| 参数排序（核心在前，必选先可选） | ✅ | `(certAlg, list, storeInfo)` |
| 数据类型名词 | ✅ | `CmCertStoreInfo`、`CmCertAlgorithm` |
| 错误码完备 | ✅ | 返回 int32_t，复用 CMR_ERROR_* |
| **注释（面向开发者）** | ⚠️ medium | `cert_manager_api.h` 新增声明缺 @brief/@param/@return 注释；建议补"按 certAlg 过滤系统 CA 并返回 certStoreInfo，certAlg 缺省 ALL" |
| `CmCertStoreInfo` 字段 | ✅ | char[] 定长版本串，caller-allocates |
| `CmCertAlgorithm` 枚举 | ✅ | ALL=0/INTERNATIONAL=1/SM=2，与客户端 d.ts 一致 |

### 客户端 d.ts（@ohos.security.certManager.d.ts）
| 规则 | 结果 | 说明 |
|---|---|---|
| `getSystemTrustedCertificateList(certAlg?: CertAlgorithm)` | ✅ | 可选参数，向后兼容 |
| `CMResult.certStoreInfo?: CertStoreInfo` | ✅ | 可选字段 |
| `CertStoreInfo { certStoreVersion; smcertStoreVersion }` | ✅ | 与需求契约一致 |
| since 标注 | ⚠️ low | 新增声明标注 `@since 20`，需与 interface_sdk-js 仓实际落点对齐（跨仓协同） |

## 3. 单元测试规划（ohos-test-ut-generation）

### 环境
- SA UT 目录：`test/unittest/src/`（已有 `cm_get_certlist_test.cpp`）
- 框架：HWTEST_F + TestSize.Level1，`using namespace testing::ext;`
- 目标函数：`CmGetSystemTrustedCertListInfo`（engine 过滤+版本号）

### 测试场景设计
| 编号 | 场景 | 输入 | 预期 | 等级 |
|---|---|---|---|---|
| T01 | 正常 certAlg=ALL | certAlg=ALL | 返回全部系统 CA，storeInfo 读取版本文件 | Level1 |
| T02 | certAlg=INTERNATIONAL | certAlg=1 | 仅返回国际证书（SM 被过滤） | Level1 |
| T03 | certAlg=SM 国内 | certAlg=2 | 仅返回国密证书 | Level1 |
| T04 | certAlg=SM 海外（无国密） | certAlg=2 + 空国密 | 返回空列表 | Level2 |
| T05 | 版本文件缺失 | 删除 cert_store_version | storeInfo 两字段为空串，不崩溃 | Level2 |
| T06 | 空入参 | certFileList=NULL | 返回 CMR_ERROR_INVALID_ARGUMENT | Level2 |

### 用例规划
| 用例 | 名称 | 场景 | 宏 |
|---|---|---|---|
| 001 | CmGetSystemTrustedCertListInfo_001 | T01 | HWTEST_F |
| 002 | CmGetSystemTrustedCertListInfo_002 | T02 | HWTEST_F |
| 003 | CmGetSystemTrustedCertListInfo_003 | T03 | HWTEST_F |
| 004 | CmGetSystemTrustedCertListInfo_004 | T04 | HWTEST_F |
| 005 | CmGetSystemTrustedCertListInfo_005 | T05 | HWTEST_F |
| 006 | CmGetSystemTrustedCertListInfo_006 | T06 | HWTEST_F |

> 客户端侧 UT 已有 `SysCaItem.test.ets`（hypium，VO 契约+分组结构+海外）。SA 侧 UT 需在 OH 源码树 `cm_sdk_test` 编译运行（Windows 不可执行）。

## 4. Fuzz 规划（ohos-test-fuzz-generation）

### 目标
`CmIpcServiceGetCertificateList`（IPC stub 入口）— 复用既有 `cmipcservicegetcertificatelist_fuzzer` 框架，扩展 certAlg 维度。

### Fuzz 用例方向
| 方向 | 输入 | 预期 |
|---|---|---|
| certAlg 越界 | 随机 uint32（含 >2） | 不崩溃；fail-safe（空列表或 INVALID_ARGUMENT） |
| paramSet 缺 certAlg tag | 仅 store | 等价 ALL，返回全部 |
| paramSet 畸形 | 随机字节 paramSetBlob | GetInputParams 返回错误，不崩溃 |
| outData 边界 | 极小 outData | CmGetCertListPack 返回 BUFFER_TOO_SMALL，不越界写 |

### 建议产物
在 `test/fuzz_test/cmipcservicegetcertificatelist_fuzzer/` 既有 fuzzer 的 corpus 中新增含 `CM_TAG_PARAM1_UINT32` 的种子；fuzzer 主入口已存在，仅需扩展 corpus 覆盖 certAlg 分支。

## 5. 汇总与建议

| 活动 | 关键发现 | 处置 |
|---|---|---|
| 安全评审 | certAlg 在 stub 边界未校验（fail-safe，MEDIUM） | 建议加边界校验（纵深防御）；遵循"已有实现能别动则别动"则可接受现状 |
| API 评审 | innerkit 新增声明缺注释（MEDIUM）；d.ts since 对齐（LOW） | 补 @brief/@param 注释；跨仓协同 since 版本 |
| UT 规划 | SA engine 过滤+版本号 6 用例规划完成 | 待 OH 源码树 cm_sdk_test 实现/运行 |
| Fuzz 规划 | 扩展既有 fuzzer corpus 覆盖 certAlg | 新增种子即可 |

> 验证限制：客户端 hvigor 编译已通过；SA 侧 UT/Fuzz/编译需 OH 源码树（Linux + GN/Ninja），本机不可执行。
