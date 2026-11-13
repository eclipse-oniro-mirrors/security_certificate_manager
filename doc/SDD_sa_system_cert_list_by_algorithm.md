# SDD：SA 侧 getSystemTrustedCertificateList 按算法查询与证书库版本号返回

> 对应客户端需求 `doc/SDD_system_ca_algorithm_grouping.md`（applications_user_certificate_manager 仓）。本仓为证书管理 SA（部件 `certificate_manager`，SA 3512），实现服务侧能力。

## 1. 背景与目标

客户端按“国际算法/国密算法”分组展示系统预置 CA 证书并显示证书库版本号，需要 SA 侧 `getSystemTrustedCertificateList` 支持：
- 新增可选入参 `certAlg?: CertAlgorithm`，按算法过滤根证书列表；
- `CMResult` 新增可选字段 `certStoreInfo?: CertStoreInfo`，返回国际/国密证书库版本号。

## 2. 需求清单

| # | 需求 | 验收点 |
|---|---|---|
| R1 | `getSystemTrustedCertificateList(certAlg?)` 支持按算法查询 | 传 `INTERNATIONAL` 只返回国际证书；传 `SM` 只返回国密证书；不传返回全部 |
| R2 | `CMResult.certStoreInfo` 返回版本号 | `certStoreInfo.certStoreVersion`（国际）、`smcertStoreVersion`（国密）非空 |
| R3 | 海外设备无国密证书时 `SM` 查询返回空列表 | `certAlg=SM` 且无国密证书时 certList 为空 |
| R4 | 向后兼容 | 旧客户端不传 `certAlg`，行为与原 `getSystemTrustedCertificateList()` 一致 |

## 3. 接口契约（与客户端 d.ts 一致）

```ts
function getSystemTrustedCertificateList(certAlg?: CertAlgorithm): Promise<CMResult>;
export interface CMResult { certStoreInfo?: CertStoreInfo; /* ...existing... */ }
export interface CertStoreInfo {
  certStoreVersion: string;    // 国际算法 CA 证书库版本号
  smcertStoreVersion: string;  // 国密算法 CA 证书库版本号
}
```

## 4. 四件套 IPC 全链路设计（遵循 AGENTS.md 架构约束）

> 复用既有消息码 `CM_MSG_GET_CERTIFICATE_LIST`（`cert_manager_service_ipc_interface_code.h:27`），在 CmParamSet 中**新增可选 tag** 携带 `certAlg`，响应 outData 尾部追加 `certStoreInfo`。不新增消息码 → 不触发 CODEOWNERS 对枚举的强审查，且旧客户端不发送该 tag 时服务端按 `CM_CERT_ALG_ALL` 处理，向后兼容。

```
NAPI CMNapiGetSystemCertList
  ├─ 解析可选 certAlg（0 或 1 个 uint32 参数）
  └─ CmGetSystemTrustedCertList(certAlg, list, &storeInfo)        [innerkit 新增]
innerkit cert_manager_api.c
  └─ CmClientGetSystemTrustedCertList(certAlg, list, storeInfo)   [IPC 客户端]
frameworks cm_ipc_client.c
  ├─ CmParamSet: { CM_TAG_PARAM0_UINT32=store, CM_TAG_PARAM1_UINT32=certAlg }
  ├─ outBlob 预留 certList + certStoreInfo 空间
  ├─ SendRequest(CM_MSG_GET_CERTIFICATE_LIST, ...)
  └─ CmCertListAndStoreInfoUnpackFromService(outBlob, list, storeInfo)  [serialization 新增]
services cm_ipc_service.c::CmIpcServiceGetCertificateList
  ├─ GetInputParams 读 store + 可选 certAlg（缺省 ALL）
  ├─ CmServiceGetCertList(context, &prop, store, certAlg, &certFileList)
  └─ CmServiceGetCertListPack(context, store, certAlg, &certFileList, &storeInfo, outData)
services cm_ipc_service_cert_pack.c::CmServiceGetCertListPack
  ├─ CmGetCertListInfo(context, store, certAlg, certFileList, &certBlob, status, &storeInfo)  [engine]
  ├─ CmGetCertListPack(...)              // 既有：打包 certList
  └─ CmCertStoreInfoPack(storeInfo, outData)  // 新增：尾部追加版本号
engine cert_manager_query.c::CmGetCertListInfo
  ├─ 枚举 /etc/security/certificates 下系统 CA
  ├─ 若 certAlg≠ALL：按证书公钥算法过滤（SM2/SM3 归国密，其余归国际）
  └─ CmGetCertStoreVersion(...) 填充 storeInfo（版本号来源：版本文件/编译宏，见 §6）
```

## 5. 受影响文件

| 文件 | 改动 |
|---|---|
| `interfaces/innerkits/.../include/cm_type.h` | 新增 `enum CmCertAlgorithm`、`struct CmCertStoreInfo`、`MAX_LEN_CERT_STORE_VERSION` |
| `interfaces/innerkits/.../include/cert_manager_api.h` | 新增 `CmGetSystemTrustedCertList(certAlg, list, storeInfo)`（保留 `CmGetCertList` 不变） |
| `interfaces/innerkits/.../source/cert_manager_api.c` | 转发 `CmClientGetSystemTrustedCertList` |
| `frameworks/.../cm_ipc/src/cm_ipc_client.c` | 新增 `CmClientGetSystemTrustedCertList`（带 certAlg + 解包 storeInfo） |
| `frameworks/.../cm_ipc/include/cm_ipc_client.h` | 新增声明 |
| `frameworks/.../cm_ipc/src/cm_ipc_client_serialization.c` | 新增 `CmCertListAndStoreInfoUnpackFromService`（或扩展既有解包） |
| `services/.../idl/cm_ipc/cm_ipc_service.c` | `CmIpcServiceGetCertificateList` 读 certAlg、传 storeInfo |
| `services/.../idl/cm_ipc/cm_ipc_service_cert_pack.c` | `CmServiceGetCertListPack` 追加 storeInfo；新增 `CmCertStoreInfoPack` |
| `services/.../engine/main/core/src/cert_manager_query.c` | `CmGetCertListInfo` 支持 certAlg 过滤 + 填 storeInfo |
| `interfaces/kits/napi/src/cm_napi_get_system_cert_list.cpp` | 解析 certAlg、调新 innerkit、序列化 `certStoreInfo` |
| `interfaces/kits/napi/include/cm_napi_common.h`（或 .cpp） | 新增属性名常量与 `GenerateCertStoreInfo` |

> 多接口形态同步：NDK（`OH_CertManager_*`）/ ANI / CJ 按本设计同步暴露（本迭代先落 NAPI + innerkit + IPC + engine，NDK/ANI/CJ 同模式跟进）。

## 6. 关键设计决策

### 6.1 算法判定
系统 CA 证书为 OpenSSL 哈希命名文件（`config/systemCertificates/`）。判定算法：解析证书公钥——SM2/SM3 归 `CM_CERT_ALG_SM`，RSA/EC/Ed25519 等归 `CM_CERT_ALG_INTERNATIONAL`。复用 `cm_x509.c` 解析能力。`certAlg=ALL` 时不过滤。

### 6.2 版本号来源
证书库版本号写入固定文件 `/etc/security/certificates/cert_store_version`（格式两行：国际版本、国密版本），由镜像构建时 `config/BUILD.gn` 预置。engine 读取该文件填充 `certStoreInfo`；文件缺失时对应字段置空串（海外设备无国密 → `smcertStoreVersion` 为空）。

### 6.3 向后兼容
- 旧客户端不发送 `certAlg` tag → `GetInputParams` 读不到 → 默认 `CM_CERT_ALG_ALL`，行为同原接口。
- 响应 outData 尾部追加 storeInfo：旧客户端 `CmCertificateListUnpackFromService` 只读 certList 长度字段，忽略尾部多余字节，不受影响。

## 7. 验收标准

1. `getSystemTrustedCertificateList(CertAlgorithm.INTERNATIONAL)` 返回的国际证书列表与 `SM` 返回的国密列表互斥且并集等于无参返回。
2. `CMResult.certStoreInfo.certStoreVersion`/`smcertStoreVersion` 与 `/etc/security/certificates/cert_store_version` 一致。
3. 海外设备（无国密证书）`SM` 查询返回空 certList，`smcertStoreVersion` 为空。
4. 旧客户端（不传 certAlg）行为不变。
5. `cm_sdk_test`/`cm_module_test` 受影响用例通过；新增 `CmGetSystemTrustedCertListByAlg` 单测 + `cmgetcertlist_fuzzer` 适配。

## 8. 验证限制

本仓为 OpenHarmony 系统组件，构建须在 OH 源码根目录 `./build.sh --product-name <product> --build-target cert_manager_service/certmanager`，Windows 无 GN+Ninja OH 工具链，**无法本地构建验证**。运行时验证须真机/模拟器 SA 3512 环境。预期验证命令与关键字：
```bash
./build.sh --product-name rk3568 --build-target certmanager
hdc shell "cm_sdk_test --gtest_filter=CmGetCertListTest.*SystemTrustedByAlg*"
hilog | grep -E "CertManager.*getSystemTrustedCertList"
```

## 9. 安全核对
- 不输出私钥/口令；版本号为公开元数据，可日志打印。
- 不破坏 IPC 兼容（仅追加可选 tag + 尾部字节）。
- 不新增跨 uid 越权路径；`CmIpcServiceGetCertificateList` 仍走 `CmServiceGetSystemCertListCheck` + `CmContext` 校验。
- 内存走 `CmMalloc/CmFree`，敏感缓冲无（版本号非敏感）。
