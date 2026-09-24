// =============================================================================
// appstore-portal/api.hpp — 契约面（架构师锁定）
// 权威源：《架构说明》§8.7/§8.8、《技术规范》§16 制品与升级。
// 职责：制品发布/灰度/激活/回滚；把 OS 状态转为可操作界面与证据出口。
// =============================================================================
#pragma once

#include <cstdint>
#include <limits>
#include <string>
#include <utility>

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
  // D2 制品闭环元数据。sha256 保留为历史兼容字段，语义等同 package_sha256。
  std::string package_sha256;
  std::string image_digest;
  std::string format;
  std::string source;

  Artifact() = default;
  Artifact(std::string id, std::string ver, std::string digest, std::string sbom,
           std::string lifecycle, std::uint64_t published,
           std::string package_digest = {}, std::string image = {},
           std::string artifact_format = {}, std::string artifact_source = {})
      : artifact_id(std::move(id)),
        version(std::move(ver)),
        sha256(std::move(digest)),
        sbom_ref(std::move(sbom)),
        status(std::move(lifecycle)),
        published_ms(published),
        package_sha256(package_digest.empty() ? sha256 : std::move(package_digest)),
        image_digest(std::move(image)),
        format(std::move(artifact_format)),
        source(std::move(artifact_source)) {}
};

struct SemVersion {
  std::uint64_t major{0};
  std::uint64_t minor{0};
  std::uint64_t patch{0};

  friend bool operator<(const SemVersion& a, const SemVersion& b) {
    if (a.major != b.major) return a.major < b.major;
    if (a.minor != b.minor) return a.minor < b.minor;
    return a.patch < b.patch;
  }
};

// 接收 X.Y 或 X.Y.Z，统一保存为 X.Y.Z。拒绝前导符号、空段、后缀和溢出。
inline bool normalize_semver(const std::string& input, std::string& normalized,
                             SemVersion* parsed = nullptr) {
  std::uint64_t parts[3]{0, 0, 0};
  std::size_t begin = 0;
  int count = 0;
  while (begin <= input.size() && count < 3) {
    const auto end = input.find('.', begin);
    const auto size = (end == std::string::npos ? input.size() : end) - begin;
    if (size == 0) return false;
    if (size > 1 && input[begin] == '0') return false;
    std::uint64_t value = 0;
    for (std::size_t i = begin; i < begin + size; ++i) {
      const char ch = input[i];
      if (ch < '0' || ch > '9') return false;
      const auto digit = static_cast<std::uint64_t>(ch - '0');
      if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) return false;
      value = value * 10 + digit;
    }
    parts[count++] = value;
    if (end == std::string::npos) break;
    begin = end + 1;
  }
  if (count < 2 || count > 3) return false;
  // count==3 时必须已经消费完整字符串；四段会在上面的循环后留下内容。
  std::size_t dots = 0;
  for (char ch : input) dots += ch == '.';
  if (dots + 1 != static_cast<std::size_t>(count)) return false;
  normalized = std::to_string(parts[0]) + "." + std::to_string(parts[1]) + "." +
               std::to_string(parts[2]);
  if (parsed) *parsed = SemVersion{parts[0], parts[1], parts[2]};
  return true;
}

// 制品校验接缝：签名/SBOM/兼容矩阵。默认桩只查摘要非空；生产实现须走 security-mgr。
class IArtifactVerifier {
 public:
  virtual ~IArtifactVerifier() = default;// 析构函数, 保证用父类指针删除子类对象时，内存安全
  // 校验制品完整性，返回是否通过，原因写入 reason。
  //const Artifact& a 表示只读引用，不修改制品数据
  virtual bool verify(const Artifact& a, std::string& reason) = 0;// virtual + =0 表示纯虚函数，必须在子类中重写
};

}  // namespace os2::store
