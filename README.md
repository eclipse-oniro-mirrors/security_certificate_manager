# 证书管理<a name="ZH-CN_TOPIC_0000001096592945"></a>

-   [简介](#section11660541593)
-   [目录](#section161941989596)
-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

证书管理主要提供系统级的证书管理能力，实现证书全生命周期（生成，存储，使用，销毁）的管理和安全使用 ，满足生态应用和上层业务的诉求。 

证书管理模块可以分为如下三大部分：

- SDK层：提供证书管理 API，供应用调用。
- Service层：实现证书全生命周期管理。
- Engine层：证书管理核心模块，负责证书的生成、存储、授权、使用、销毁等工作。其中密钥相关操作依赖于当前设备中的HUKS能力，证书管理通过HUKS组件提供对业务证书以及其关联密钥的生成，导入，存储，读取和删除等能力。 

## 目录<a name="section161941989596"></a>

```
base/security/certificate_manager/
├── build                             # 编译配置文件
├── config                            # 系统根证书文件
├── frameworks                        # 框架代码, 作为基础功能目录, 被interfaces和services使用.
├── interfaces                        # 接口API代码
│   └── innerkits
│   └── kits
├── services
│   └── cert_manager_standard         # 证书管理核心功能代码
├── test                              # 测试资源存放目录
```

## 相关仓<a name="section1371113476307"></a>

**安全子系统**

**security_huks**

