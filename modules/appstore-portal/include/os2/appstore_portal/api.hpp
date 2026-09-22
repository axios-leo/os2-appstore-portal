// =============================================================================
// appstore-portal/api.hpp — 契约面（架构师锁定）
// 权威源：《架构说明》§8.7/§8.8、《技术规范》§16 制品与升级。
// 职责：制品发布/灰度/激活/回滚；把 OS 状态转为可操作界面与证据出口。
// =============================================================================
#pragma once

#include <cstdint>
#include <string>

namespace os2::store {//namespace相当于package，给类起个名字，方便命名空间管理

//定义制品结构体，包含制品编码、版本、完整性摘要、SBOM 引用、状态、发布时间。
//实现校验接口，用于校验制品完整性。

struct Artifact {
  std::string artifact_id;    // 制品编码
  std::string version;
  std::string sha256;         // 完整性摘要（签名校验 M1 接 security-mgr）（确认文件没有被篡改，传输没损坏）
  std::string sbom_ref;       // SBOM 引用（记录i这个包里包含哪些依赖、开源组件、版本、许可证）
  std::string status;         // published/activated/rolled-back（三种状态）
  std::uint64_t published_ms{0};
};

// 制品校验接缝：签名/SBOM/兼容矩阵。默认桩只查摘要非空；生产实现须走 security-mgr。
class IArtifactVerifier {
 public:
  virtual ~IArtifactVerifier() = default;// 析构函数, 保证用父类指针删除子类对象时，内存安全
  // 校验制品完整性，返回是否通过，原因写入 reason。
  //const Artifact& a 表示只读引用，不修改制品数据
  virtual bool verify(const Artifact& a, std::string& reason) = 0;// virtual + =0 表示纯虚函数，必须在子类中重写
};

}  // namespace os2::store
