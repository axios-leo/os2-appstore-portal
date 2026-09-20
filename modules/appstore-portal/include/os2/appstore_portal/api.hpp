// =============================================================================
// appstore-portal/api.hpp — 契约面（架构师锁定）
// 权威源：《架构说明》§8.7/§8.8、《技术规范》§16 制品与升级。
// 职责：制品发布/灰度/激活/回滚；把 OS 状态转为可操作界面与证据出口。
// =============================================================================
#pragma once

#include <cstdint>
#include <string>

namespace os2::store {

struct Artifact {
  std::string artifact_id;    // 制品编码
  std::string version;
  std::string sha256;         // 完整性摘要（签名校验 M1 接 security-mgr）
  std::string sbom_ref;       // SBOM 引用
  std::string status;         // published/activated/rolled-back
  std::uint64_t published_ms{0};
};

// 制品校验接缝：签名/SBOM/兼容矩阵。默认桩只查摘要非空；生产实现须走 security-mgr。
class IArtifactVerifier {
 public:
  virtual ~IArtifactVerifier() = default;
  virtual bool verify(const Artifact& a, std::string& reason) = 0;
};

}  // namespace os2::store
