// =============================================================================
// impl/signature_verifier.hpp — 制品 X.509 签名验证（M2.3；CERT_MANAGEMENT.md §5 商店检查）
//
// 组合在既有格式/摘要校验之上：security.sig_algo=x509 时追加"证书链+有效期+签名"验证；
// 缺省（hmac/未配置）只走内层格式校验 = 存量行为零变化（opt-in，非破坏）。
//
// 签名材料走文件系统（签名目录/<artifact_id>.sig + signer.crt + ca.crt）——制品供应链
// 本就是文件；verify(Artifact) 已带 artifact_id + sha256，足以定位并验签，**不改契约面**。
//
// 验签实现：机器自动执行（openssl CLI，经 tools/verify_artifact.sh）。后端接缝可注入，
// 单测用假后端验证决策逻辑而不实跑 openssl（L1 门禁在 WSL 无 openssl 亦常绿）。
// 进程内验签（libcrypto/mbedTLS）为硬化项——按三段制归 1.5期（量产一致，负责人主导）。
//
// F-06 去 shell 化（量产差距重审 R2，负责人授权）：外部脚本改经 posix_spawn 以 argv
// 数组直传，不再拼接 shell 命令串——制品 id/摘要即便含 shell 元字符也只是普通位置实参，
// 命令注入面**结构性消除**（不再依赖上游转义/白名单兜底）。准入层字符集白名单保留为纵深。
// =============================================================================
#pragma once

#include <memory>
#include <string>

#include "os2/appstore_portal/api.hpp"
#include "os2/platform/x509.hpp"

namespace os2::store::impl {

// 验签后端接缝（可注入：生产=openssl；单测=假后端）
class ISignatureCheck {
 public:
  virtual ~ISignatureCheck() = default;
  // 对 <artifact_id> 的 sha256 摘要验链+签名；通过返回 true，否则 reason 填因。
  virtual bool check(const std::string& artifact_id, const std::string& sha256,
                     std::string& reason) = 0;
};

// openssl CLI 后端：签名目录按 artifact_id 定位 .sig，对 sha256 验链+签名。
// 运行期需 openssl + tools/verify_artifact.sh 就位（部署镜像装配，见 commit 2/CERT_MANAGEMENT）。
class OpensslSignatureCheck : public ISignatureCheck {
 public:
  OpensslSignatureCheck(std::string sign_dir, std::string ca_bundle, std::string script)
      : sign_dir_(std::move(sign_dir)), ca_(std::move(ca_bundle)), script_(std::move(script)) {}

  bool check(const std::string& id, const std::string& sha256, std::string& reason) override {
    const std::string sig = sign_dir_ + "/" + id + ".sig";
    const std::string cert = sign_dir_ + "/signer.crt";
    const std::string ca = ca_.empty() ? (sign_dir_ + "/ca.crt") : ca_;
    // spawn 核心提为 platform x509::spawn_verify_script（X509 方案 ②：与命令门共用
    // 同一后端族，1.5期 mbedTLS 落地一次两处受益）；argv 直传语义与拒因串原样保持。
    const int rc = x509::spawn_verify_script(script_, sha256, sig, cert, ca);
    if (rc == -1) { reason = "x509 verify spawn failed for " + id; return false; }
    if (rc != 0) { reason = "x509 signature/chain verify failed for " + id; return false; }
    return true;
  }

 private:
  std::string sign_dir_, ca_, script_;
};

// 组合校验器：内层（格式/摘要）过后，x509 启用时追加签名验证。
class SignatureArtifactVerifier : public IArtifactVerifier {
 public:
  SignatureArtifactVerifier(std::unique_ptr<IArtifactVerifier> inner,
                            std::unique_ptr<ISignatureCheck> sig, bool enabled)
      : inner_(std::move(inner)), sig_(std::move(sig)), enabled_(enabled) {}

  bool verify(const Artifact& a, std::string& reason) override {
    if (!inner_->verify(a, reason)) return false;          // ① 格式/摘要先过（存量校验）
    if (!enabled_) return true;                            // 缺省(hmac)：只格式校验，行为不变
    return sig_->check(a.artifact_id, a.sha256, reason);   // ② x509：证书链+有效期+签名
  }

 private:
  std::unique_ptr<IArtifactVerifier> inner_;
  std::unique_ptr<ISignatureCheck> sig_;
  bool enabled_;
};

}  // namespace os2::store::impl
