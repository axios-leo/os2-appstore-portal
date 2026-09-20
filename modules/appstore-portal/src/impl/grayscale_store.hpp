// =============================================================================
// impl/grayscale_store.hpp — 应用商店基本实现：摘要校验强化 + 灰度激活 + 回滚点
// 灰度：激活按 10%→50%→100% 三批推进。两种投放口径（store.rollout_mode）：
//   immediate（缺省）= 三批即时留痕（台架/演示存量口径零变化）；
//   staged（opt-in）= 真实分批：每批经观察窗（store.rollout_step_ms）再推进，
//   窗内总线出现 error/critical 告警 → 健康门控停批并经 ActivationCommand
//   自动回滚（与人工回滚同一 PolicyCheck 审计门）。
// 规约：《技术规范》§16.4 灰度与回滚；《架构说明》§7.1 岸上软件工厂更新。
// =============================================================================
#pragma once

#include <array>

#include <cctype>

#include "os2/platform/hash.hpp"
#include "impl/signature_verifier.hpp"
#include "store_service.hpp"

namespace os2::store::impl {

// M1.2 收紧为真摘要准入：sha256 必须 64 位 hex（此前 ≥8 的格式宽检退役），
// 制品 id 必须统一编码前缀——软件工厂分发的完整性前提（KPI-岸上更新安全）。
class Sha256FormatVerifier : public IArtifactVerifier {
 public:
  bool verify(const Artifact& a, std::string& reason) override {
    /* M5 说明：制品 id 走软件工厂命名空间，同上不随模型 id 制式改。 */
    if (a.artifact_id.rfind("os2.", 0) != 0 && a.artifact_id.rfind("qt.", 0) != 0) {
      reason = "artifact_id must use unified code prefix (os2./qt.)";
      return false;
    }
    // F-06 收紧（量产差距重审在案缺陷）：id 字符集白名单 alnum/._- 且限长——
    // id 会拼入验签路径与外部调用，shell 元字符/路径穿越在准入层出局
    if (a.artifact_id.size() > 128) { reason = "artifact_id too long (>128)"; return false; }
    for (char ch : a.artifact_id)
      if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '.' && ch != '_' && ch != '-') {
        reason = "artifact_id has illegal char (allowed: alnum . _ -)";
        return false;
      }
    if (a.sha256.size() != 64) { reason = "sha256 must be 64 hex chars"; return false; }
    for (char c : a.sha256)
      if (!std::isxdigit(static_cast<unsigned char>(c))) { reason = "sha256 not hex"; return false; }
    if (a.version.empty()) { reason = "version required"; return false; }
    return true;
  }
};

// 制品封签/复核（M1.2）：发布方 seal(content) 得真摘要，接收/激活侧
// verify_content 复核——分发路径任何篡改（内容或摘要单边改动）都会被拦下。
struct ArtifactSealer {
  static std::string seal(const std::string& content) { return os2::hash::sha256_hex(content); }
  static bool verify_content(const Artifact& a, const std::string& content) {
    return os2::hash::sha256_hex(content) == a.sha256;
  }
};

class GrayscaleStore : public StoreService {
 public:
  using StoreService::StoreService;
  const std::vector<std::string>& rollout_log() const { return rollout_; }
  bool rollout_in_flight() const { return in_flight_; }

 protected:
  bool on_init() override {
    if (!StoreService::on_init()) return false;
    staged_ = config().get("store.rollout_mode", "immediate") == "staged";
    // 健康门控只在 staged 模式接线：immediate 存量路径不多一条订阅
    if (staged_)
      mgmt().subscribe(topics::AlarmEvent, [this](const Msg& m) { gate_on_alarm(event_from(m)); });
    return true;
  }

  std::unique_ptr<IArtifactVerifier> make_verifier() override {
    auto inner = std::make_unique<Sha256FormatVerifier>();
    // 缺省（sig_algo≠x509）：只格式/摘要校验，存量行为零变化。
    if (config().get("security.sig_algo") != "x509") return inner;
    // x509 opt-in：组合"证书链+有效期+签名"验证（CERT_MANAGEMENT.md §5 商店检查）。
    auto sig = std::make_unique<OpensslSignatureCheck>(
        config().get("store.sign_dir", "deploy/certs"),
        config().get("store.ca_bundle"),
        config().get("store.verify_script", "tools/verify_artifact.sh"));
    return std::make_unique<SignatureArtifactVerifier>(std::move(inner), std::move(sig), true);
  }
  void on_activated(const Artifact& a) override {
    if (!staged_) {
      for (int pct : kBatches) push_batch(a.artifact_id, a.version, pct);
      return;
    }
    // staged：激活 = 首批投放，后续批次由观察窗推进（on_tick）
    cur_id_ = a.artifact_id;
    cur_ver_ = a.version;
    batch_idx_ = 0;
    batch_start_ = now_ms();
    in_flight_ = true;
    push_batch(cur_id_, cur_ver_, kBatches[0]);
  }

  void on_tick(std::uint64_t now) override {
    persist_tick(now);  // F-07 D2：制品/激活态节拍落盘（先于灰度早退，不受其短路）
    if (!in_flight_ || now - batch_start_ < config().get_u64("store.rollout_step_ms", 2000)) return;
    ++batch_idx_;
    batch_start_ = now;
    push_batch(cur_id_, cur_ver_, kBatches[batch_idx_]);
    if (batch_idx_ + 1 >= kBatches.size()) {
      in_flight_ = false;
      emit_event("rollout_completed", "info", "activated", cur_id_ + "@" + cur_ver_);
    }
  }

 private:
  // 健康门控：观察窗内任一 error/critical 告警 → 停批 + 自动回滚。
  // 回滚不直改状态，而是自请求 ActivationCommand——与人工回滚同一 PolicyCheck
  // 审计门（同 device 收编的 ProgramControlCommand 自请求模式）。
  void gate_on_alarm(const Event& e) {
    if (!in_flight_ || e.level.empty() || e.source == identity().service_id) return;
    if (config().get("store.rollout_halt_levels", "error,critical").find(e.level) ==
        std::string::npos)
      return;
    in_flight_ = false;  // 先收状态：回滚路径上的再入告警不重复触发
    rollout_.push_back(cur_id_ + "@" + cur_ver_ + " -> halted@" +
                       std::to_string(kBatches[batch_idx_]) + "% (" + e.source + ":" +
                       e.event_type + ")");
    emit_event("rollout_halted", "warn", "rolling-back",
               cur_id_ + " on " + e.level + " from " + e.source, e.trace_id);
    Command rb{gen_id("cmd"), cur_id_, "rollback", "{}",
               config().get("store.rollback_subject", identity().service_id),
               "auto-halt", 0, e.trace_id};
    auto rep = mgmt().request(topics::ActivationCommand, to_msg(rb), 500);
    if (!rep || !reply_from(*rep).ok())
      emit_event("rollout_rollback_failed", "error", "halted", cur_id_, e.trace_id);
  }

  void push_batch(const std::string& id, const std::string& ver, int pct) {
    rollout_.push_back(id + "@" + ver + " -> " + std::to_string(pct) + "%");
    emit_metric("store.rollout_pct", pct, "{\"artifact\":\"" + id + "\"}");
  }

  static constexpr std::array<int, 3> kBatches{10, 50, 100};

  std::vector<std::string> rollout_;
  bool staged_{false};
  bool in_flight_{false};
  std::string cur_id_, cur_ver_;
  std::size_t batch_idx_{0};
  std::uint64_t batch_start_{0};
};

}  // namespace os2::store::impl
