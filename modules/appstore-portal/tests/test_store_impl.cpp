#include <sys/stat.h>

#include <cstdio>
#include <fstream>

#include "impl/grayscale_store.hpp"
#include "os2/platform/testing.hpp"
using namespace os2;
using namespace os2::store::impl;

OS2_TEST(sha_format_enforced_and_grayscale_rollout) {
  ServiceContext ctx{BusPair::make_inproc(), Config{}};
  ctx.buses.mgmt->serve(topics::PolicyCheck,
      [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
  GrayscaleStore s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
  OS2_ASSERT(s.init() && s.start());
  auto bad = ctx.buses.mgmt->request(topics::ArtifactPublish,
      Msg{"A", {{"artifact_id", "qt.pkg.app"}, {"version", "1.0"}, {"sha256", "zz!"}}}, 100);
  OS2_ASSERT(bad && bad->get("accepted") == "false");
  ctx.buses.mgmt->request(topics::ArtifactPublish,  // M1.2 起须 64 位真摘要 + 统一前缀
      Msg{"A", {{"artifact_id", "qt.pkg.app"}, {"version", "1.0"},
                {"sha256", ArtifactSealer::seal("app-1.0-content")}}}, 100);
  Command act{gen_id("cmd"), "qt.pkg.app", "activate", "{}", "release", "ctx", 0, "t"};
  auto r = ctx.buses.mgmt->request(topics::ActivationCommand, to_msg(act), 100);
  OS2_ASSERT(r && reply_from(*r).ok());
  OS2_ASSERT_EQ(s.rollout_log().size(), std::size_t{3});
  OS2_ASSERT(s.rollout_log().back().find("100%") != std::string::npos);
}
int main() { return os2::testing::run_all(); }

// ---- M1.2 真摘要准入 + 封签复核 ----
OS2_TEST(strict_digest_and_sealer) {
  Sha256FormatVerifier v;
  std::string why;
  os2::store::Artifact bad1{"qt.pkg.x", "1.0", "abcd1234", "", "published", 0};   // 非 64 位
  OS2_ASSERT(!v.verify(bad1, why));
  os2::store::Artifact bad2{"pkg-x", "1.0", std::string(64, 'a'), "", "published", 0};  // 无统一前缀
  OS2_ASSERT(!v.verify(bad2, why));

  const std::string content = "artifact-binary-content-v1";
  os2::store::Artifact good{"qt.pkg.x", "1.0", ArtifactSealer::seal(content), "", "published", 0};
  OS2_ASSERT(v.verify(good, why));
  OS2_ASSERT(ArtifactSealer::verify_content(good, content));          // 完整闭环
  OS2_ASSERT(!ArtifactSealer::verify_content(good, content + "x"));   // 内容篡改被拦
}

// ---- M2.3 X.509 制品签名验证（CERT_MANAGEMENT.md §5；决策逻辑，假后端 hermetic）----
#include "impl/signature_verifier.hpp"
namespace {
struct PassInner : os2::store::IArtifactVerifier {  // 内层格式校验：恒过
  bool verify(const os2::store::Artifact&, std::string&) override { return true; }
};
struct FakeSig : os2::store::impl::ISignatureCheck {
  bool ok;
  std::string last_id;
  explicit FakeSig(bool o) : ok(o) {}
  bool check(const std::string& id, const std::string&, std::string& reason) override {
    last_id = id;
    if (!ok) reason = "fake reject";
    return ok;
  }
};
os2::store::Artifact mk() { return {"os2.pkg.x", "1.0", std::string(64, 'a'), "", "published", 0}; }
}  // namespace

OS2_TEST(x509_verifier_accepts_when_signature_ok) {
  auto sig = std::make_unique<FakeSig>(true);
  FakeSig* raw = sig.get();
  SignatureArtifactVerifier v{std::make_unique<PassInner>(), std::move(sig), /*enabled=*/true};
  std::string why;
  auto a = mk();
  OS2_ASSERT(v.verify(a, why));
  OS2_ASSERT_EQ(raw->last_id, std::string("os2.pkg.x"));  // 确实调了签名后端
}

OS2_TEST(x509_verifier_rejects_when_signature_bad) {
  SignatureArtifactVerifier v{std::make_unique<PassInner>(), std::make_unique<FakeSig>(false),
                              /*enabled=*/true};
  std::string why;
  auto a = mk();
  OS2_ASSERT(!v.verify(a, why));               // 签名不过 → 拒绝入库
  OS2_ASSERT(why.find("fake reject") != std::string::npos);
}

// ---- 灰度真实批次投放 + 健康门控（staged opt-in；缺省 immediate 存量口径不变）----
namespace {
GrayscaleStore make_staged_store(ServiceContext& ctx) {
  ctx.buses.mgmt->serve(topics::PolicyCheck,
      [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
  return GrayscaleStore{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""},
                        ctx};
}
void publish_and_activate(ServiceContext& ctx) {
  ctx.buses.mgmt->request(topics::ArtifactPublish,
      Msg{"A", {{"artifact_id", "qt.pkg.app"}, {"version", "2.0"},
                {"sha256", ArtifactSealer::seal("app-2.0-content")}}}, 100);
  Command act{gen_id("cmd"), "qt.pkg.app", "activate", "{}", "release", "ctx", 0, "t"};
  auto r = ctx.buses.mgmt->request(topics::ActivationCommand, to_msg(act), 100);
  OS2_ASSERT(r && reply_from(*r).ok());
}
}  // namespace

OS2_TEST(staged_rollout_advances_per_observation_window) {
  ServiceContext ctx{BusPair::make_inproc(),
                     Config{{{"store.rollout_mode", "staged"}, {"store.rollout_step_ms", "100"}}}};
  auto s = make_staged_store(ctx);
  OS2_ASSERT(s.init() && s.start());
  publish_and_activate(ctx);
  OS2_ASSERT_EQ(s.rollout_log().size(), std::size_t{1});  // 激活=首批 10%，不再三批即时
  OS2_ASSERT(s.rollout_in_flight());
  const auto t0 = now_ms();
  s.tick(t0 + 50);                                        // 观察窗未满 → 不推进
  OS2_ASSERT_EQ(s.rollout_log().size(), std::size_t{1});
  s.tick(t0 + 150);                                       // → 50%
  s.tick(t0 + 300);                                       // → 100%，完批
  OS2_ASSERT_EQ(s.rollout_log().size(), std::size_t{3});
  OS2_ASSERT(!s.rollout_in_flight());
  OS2_ASSERT_EQ(s.find("qt.pkg.app")->status, std::string("activated"));
  s.tick(t0 + 999);                                       // 完批后不再增长
  OS2_ASSERT_EQ(s.rollout_log().size(), std::size_t{3});
}

OS2_TEST(staged_rollout_halted_by_alarm_and_rolled_back) {
  ServiceContext ctx{BusPair::make_inproc(), Config{{{"store.rollout_mode", "staged"}}}};
  auto s = make_staged_store(ctx);
  OS2_ASSERT(s.init() && s.start());
  publish_and_activate(ctx);
  OS2_ASSERT(s.rollout_in_flight());
  // info 级不构成门控输入：仍在批
  ctx.buses.mgmt->publish(topics::AlarmEvent,
      to_msg(Event{"qt.svc.other", "note", "info", "ok", "benign", now_ms(), "t0"}));
  OS2_ASSERT(s.rollout_in_flight());
  // 观察窗内业务侧 error 告警 → 停批 + 经 ActivationCommand 自动回滚
  ctx.buses.mgmt->publish(topics::AlarmEvent,
      to_msg(Event{"qt.svc.victim", "crash_loop", "error", "down", "after update",
                   now_ms(), "t1"}));
  OS2_ASSERT(!s.rollout_in_flight());
  OS2_ASSERT_EQ(s.find("qt.pkg.app")->status, std::string("rolled-back"));
  OS2_ASSERT(s.rollout_log().back().find("halted@10%") != std::string::npos);
  s.tick(now_ms() + 10000);  // 停批后窗口再大也不推进
  OS2_ASSERT(s.rollout_log().back().find("halted@10%") != std::string::npos);
}

OS2_TEST(x509_disabled_is_format_only) {  // 缺省关：即使后端会拒也不调用，仍放行（存量不变）
  auto sig = std::make_unique<FakeSig>(false);
  FakeSig* raw = sig.get();
  SignatureArtifactVerifier v{std::make_unique<PassInner>(), std::move(sig), /*enabled=*/false};
  std::string why;
  auto a = mk();
  OS2_ASSERT(v.verify(a, why));                // 只走内层格式校验 → 放行
  OS2_ASSERT(raw->last_id.empty());            // 未触碰签名后端
}

// ---- F-06 准入层字符集白名单（量产差距重审在案缺陷，R1 批收紧）----
// id 会拼入验签路径与外部调用：shell 元字符/空格/引号在准入层必须出局
OS2_TEST(artifact_id_charset_whitelist_blocks_shell_metachars) {
  ServiceContext ctx{BusPair::make_inproc(), Config{}};
  ctx.buses.mgmt->serve(topics::PolicyCheck,
      [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
  GrayscaleStore s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
  OS2_ASSERT(s.init() && s.start());
  const std::string sha = ArtifactSealer::seal("c");
  const char* bad_ids[] = {"os2.x';rm -rf x'", "qt.pkg app", "os2.a$(x)",
                           "qt.pkg\"q\"", "os2.a/../../etc"};
  for (const char* id : bad_ids) {
    auto r = ctx.buses.mgmt->request(topics::ArtifactPublish,
        Msg{"A", {{"artifact_id", id}, {"version", "1.0"}, {"sha256", sha}}}, 100);
    OS2_ASSERT(r && r->get("accepted") == "false");
  }
  auto ok = ctx.buses.mgmt->request(topics::ArtifactPublish,  // 合法字符集照常放行
      Msg{"A", {{"artifact_id", "qt.pkg.app-2_1"}, {"version", "1.0"}, {"sha256", sha}}}, 100);
  OS2_ASSERT(ok && ok->get("accepted") == "true");
}

// ---- F-06 去 shell 化：真后端注入抵抗（量产差距重审 R2，负责人授权）----
// 用真 OpensslSignatureCheck，制品 id 携 shell 注入载荷：argv 直传下载荷不应被执行
OS2_TEST(x509_backend_de_shelled_resists_command_injection) {
  const std::string dir = "/tmp/os2_f06_deshell_test";
  mkdir(dir.c_str(), 0777);
  const std::string script = dir + "/verify_ok.sh";
  { std::ofstream s(script); s << "#!/bin/sh\nexit 0\n"; }  // 恒"验签通过"的桩脚本
  const std::string sentinel = dir + "/PWNED";
  std::remove(sentinel.c_str());
  OpensslSignatureCheck sc{dir, "", script};
  std::string reason;
  // 老式 shell 拼接会在此闭合引号执行 touch；argv 直传则原样作为 .sig 路径实参
  const std::string evil = "a'; touch " + sentinel + "; echo '";
  sc.check(evil, "deadbeef", reason);  // 返回值非本用例关注（脚本恒 0）
  std::ifstream probe(sentinel);
  OS2_ASSERT(!probe.good());  // sentinel 未被创建 = 注入未执行 = 去 shell 化生效
}

// ---- F-07 D2（R0 §4-1）：制品/激活态落盘 → 重启恢复；缺省关零变化 ----
OS2_TEST(store_state_persists_and_restores_f07) {
  const std::string path = "/tmp/os2_store_persist_test.tsv";
  std::remove(path.c_str());
  Config cfg;
  cfg.set("store.persist_path", path);
  cfg.set("store.persist_ms", "0");  // 每 tick 都落盘（测试便利）
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    ctx.buses.mgmt->serve(topics::PolicyCheck, [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
    GrayscaleStore s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(s.init() && s.start());
    ctx.buses.mgmt->request(topics::ArtifactPublish,
        Msg{"A", {{"artifact_id", "qt.pkg.app"}, {"version", "1.0"},
                  {"sha256", ArtifactSealer::seal("c1")}, {"sbom_ref", "sbom://1"}}}, 100);
    Command act{gen_id("cmd"), "qt.pkg.app", "activate", "{}", "release", "ctx", 0, "t"};
    ctx.buses.mgmt->request(topics::ActivationCommand, to_msg(act), 100);
    s.stop();  // on_stop 强制落盘
  }
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    ctx.buses.mgmt->serve(topics::PolicyCheck, [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
    GrayscaleStore s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(s.init() && s.start());  // init 恢复
    auto a = s.find("qt.pkg.app");
    OS2_ASSERT(a.has_value());
    OS2_ASSERT_EQ(a->status, std::string("activated"));   // 激活态跨重启存活
    OS2_ASSERT_EQ(a->version, std::string("1.0.0"));
    OS2_ASSERT_EQ(a->sbom_ref, std::string("sbom://1"));
  }
  std::remove(path.c_str());
}

OS2_TEST(multiple_versions_are_indexed_and_restored_independently) {
  const std::string path = "/tmp/os2_store_multiversion_test.tsv";
  std::remove(path.c_str());
  Config cfg;
  cfg.set("store.persist_path", path);
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    GrayscaleStore s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(s.init() && s.start());
    auto publish_version = [&](const std::string& version, const std::string& content) {
      auto reply = ctx.buses.mgmt->request(
          topics::ArtifactPublish,
          Msg{"A", {{"artifact_id", "qt.pkg.multi"}, {"version", version},
                    {"sha256", ArtifactSealer::seal(content)},
                    {"sbom_ref", "sbom://" + version}}},
          100);
      OS2_ASSERT(reply && reply->get("accepted") == "true");
    };
    publish_version("1.0", "v1");
    publish_version("2.0", "v2");
    OS2_ASSERT_EQ(s.find("qt.pkg.multi")->version, std::string("2.0.0"));
    OS2_ASSERT_EQ(s.find("qt.pkg.multi", "1.0")->sha256, ArtifactSealer::seal("v1"));
    OS2_ASSERT_EQ(s.find("qt.pkg.multi", "2.0")->sha256, ArtifactSealer::seal("v2"));
    s.stop();
  }
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    GrayscaleStore s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(s.init() && s.start());
    OS2_ASSERT_EQ(s.find("qt.pkg.multi")->version, std::string("2.0.0"));
    OS2_ASSERT(s.find("qt.pkg.multi", "1.0").has_value());
    OS2_ASSERT(s.find("qt.pkg.multi", "2.0").has_value());
  }
  std::remove(path.c_str());
}

OS2_TEST(persisted_fields_cannot_inject_tsv_records) {
  const std::string path = "/tmp/os2_store_tsv_injection_test.tsv";
  std::remove(path.c_str());
  const std::string injected_id = "qt.pkg.injected";
  const std::string malicious_sbom =
      "sbom://safe\nA\t" + injected_id + "\t9.9\t" + ArtifactSealer::seal("fake") +
      "\tsbom://fake\tactivated\t0";
  Config cfg;
  cfg.set("store.persist_path", path);
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    GrayscaleStore s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(s.init() && s.start());
    auto reply = ctx.buses.mgmt->request(
        topics::ArtifactPublish,
        Msg{"A", {{"artifact_id", "qt.pkg.safe"}, {"version", "1.0"},
                  {"sha256", ArtifactSealer::seal("safe")}, {"sbom_ref", malicious_sbom}}},
        100);
    OS2_ASSERT(reply && reply->get("accepted") == "true");
    s.stop();
  }
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    GrayscaleStore s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(s.init() && s.start());
    const auto safe = s.find("qt.pkg.safe", "1.0");
    OS2_ASSERT(safe.has_value());
    OS2_ASSERT_EQ(safe->sbom_ref, malicious_sbom);
    OS2_ASSERT(!s.find(injected_id).has_value());
  }
  std::remove(path.c_str());
}

OS2_TEST(legacy_v1_state_file_remains_readable) {
  const std::string path = "/tmp/os2_store_legacy_v1_test.tsv";
  std::remove(path.c_str());
  const std::string digest = ArtifactSealer::seal("legacy");
  {
    std::ofstream out(path);
    out << "A\tqt.pkg.legacy\t1.2\t" << digest
        << "\tsbom://legacy\tactivated\t123\n"
        << "R\tqt.pkg.legacy\n";
  }
  Config cfg;
  cfg.set("store.persist_path", path);
  ServiceContext ctx{BusPair::make_inproc(), cfg};
  GrayscaleStore s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
  OS2_ASSERT(s.init() && s.start());
  const auto restored = s.find("qt.pkg.legacy", "1.2");
  OS2_ASSERT(restored.has_value());
  OS2_ASSERT_EQ(restored->sha256, digest);
  OS2_ASSERT_EQ(restored->sbom_ref, std::string("sbom://legacy"));
  OS2_ASSERT_EQ(s.find("qt.pkg.legacy")->version, std::string("1.2"));
  std::remove(path.c_str());
}

namespace {
const std::string kImageDigest = "sha256:" + std::string(64, 'b');

Config d2_config(const std::string& persist_path = {}) {
  Config cfg;
  cfg.set("store.deployment_enabled", "true");
  cfg.set("store.default_target", "compute-01");
  cfg.set("store.default_instance", "svc-01");
  cfg.set("store.repository_dir", "/var/lib/os2/artifacts");
  if (!persist_path.empty()) cfg.set("store.persist_path", persist_path);
  return cfg;
}

Msg publish_d2(ServiceContext& ctx, const std::string& id, const std::string& version,
               const std::string& format = "oci", const std::string& image = kImageDigest) {
  auto reply = ctx.buses.mgmt->request(
      topics::ArtifactPublish,
      Msg{"ArtifactPublish", {{"artifact_id", id}, {"version", version},
                              {"sha256", ArtifactSealer::seal(id + version)},
                              {"image_digest", image}, {"format", format},
                              {"source", "factory-A"}, {"sbom_ref", "sbom://" + version}}},
      100);
  OS2_ASSERT(reply.has_value());
  return *reply;
}

Msg activate_d2(ServiceContext& ctx, const std::string& id, const std::string& mode,
                const std::string& action = "activate", const std::string& version = {}) {
  Command command{gen_id("cmd"), id, action, "{}", "release", "ctx", 0, gen_id("trace")};
  Msg request = to_msg(command);
  request.kv["target_node"] = "compute-01";
  request.kv["instance_id"] = "svc-01";
  request.kv["mode"] = mode;
  if (!version.empty()) request.kv["version"] = version;
  auto reply = ctx.buses.mgmt->request(topics::ActivationCommand, request, 100);
  OS2_ASSERT(reply.has_value());
  return *reply;
}

void report_running(ServiceContext& ctx, const Msg& activation,
                    const std::string& id, const std::string& version,
                    const std::string& image = kImageDigest) {
  ctx.buses.mgmt->publish(
      topics::ArtifactDeployReport,
      Msg{"ArtifactDeployReport", {{"deployment_id", activation.get("effective_value")},
                                    {"artifact_id", id}, {"version", version},
                                    {"target_node", "compute-01"},
                                    {"instance_id", "svc-01"}, {"stage", "running"},
                                    {"observed_image_digest", image},
                                    {"reporter", "service"},
                                    {"timestamp", std::to_string(now_ms())}}});
}
}  // namespace

OS2_TEST(d2_semver_metadata_and_latest_selection) {
  std::string normalized;
  OS2_ASSERT(os2::store::normalize_semver("1.9", normalized));
  OS2_ASSERT_EQ(normalized, std::string("1.9.0"));
  OS2_ASSERT(!os2::store::normalize_semver("1", normalized));
  OS2_ASSERT(!os2::store::normalize_semver("01.2", normalized));
  OS2_ASSERT(!os2::store::normalize_semver("1.2.3.4", normalized));

  ServiceContext ctx{BusPair::make_inproc(), Config{}};
  GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
  OS2_ASSERT(store.init() && store.start());
  OS2_ASSERT_EQ(publish_d2(ctx, "qt.pkg.semver", "1.10").get("accepted"), std::string("true"));
  OS2_ASSERT_EQ(publish_d2(ctx, "qt.pkg.semver", "1.9").get("accepted"), std::string("true"));
  OS2_ASSERT_EQ(store.find("qt.pkg.semver")->version, std::string("1.10.0"));
  const auto artifact = store.find("qt.pkg.semver", "1.10");
  OS2_ASSERT(artifact.has_value());
  OS2_ASSERT_EQ(artifact->package_sha256, artifact->sha256);
  OS2_ASSERT_EQ(artifact->image_digest, kImageDigest);
  OS2_ASSERT_EQ(artifact->source, std::string("factory-A"));
  OS2_ASSERT_EQ(publish_d2(ctx, "qt.pkg.bad-oci", "1.0", "oci", "").get("accepted"),
                std::string("false"));
}

OS2_TEST(d2_same_version_metadata_is_immutable_and_retry_is_idempotent) {
  ServiceContext ctx{BusPair::make_inproc(), Config{}};
  GrayscaleStore store{
      ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
  OS2_ASSERT(store.init() && store.start());

  const Msg first = publish_d2(ctx, "qt.pkg.immutable", "1.0");
  OS2_ASSERT_EQ(first.get("accepted"), std::string("true"));
  const Msg retry = publish_d2(ctx, "qt.pkg.immutable", "1.0");
  OS2_ASSERT_EQ(retry.get("accepted"), std::string("true"));

  const Msg changed = publish_d2(ctx, "qt.pkg.immutable", "1.0", "oci",
                                 "sha256:" + std::string(64, 'c'));
  OS2_ASSERT_EQ(changed.get("accepted"), std::string("false"));
  OS2_ASSERT(changed.get("reason").find("different metadata") != std::string::npos);
  const auto stored = store.find("qt.pkg.immutable", "1.0");
  OS2_ASSERT(stored.has_value());
  OS2_ASSERT_EQ(stored->image_digest, kImageDigest);
}

OS2_TEST(d2_activation_requires_correlated_runtime_evidence) {
  std::vector<Msg> requests;
  ServiceContext ctx{BusPair::make_inproc(), d2_config()};
  ctx.buses.mgmt->serve(topics::PolicyCheck,
      [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
  ctx.buses.mgmt->serve(topics::ArtifactDeploy, [&](const Msg& m) {
    requests.push_back(m);
    return Msg{"ArtifactDeployReply", {{"accepted", "true"}, {"reason_code", errc::OK}}};
  });
  GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
  OS2_ASSERT(store.init() && store.start());
  OS2_ASSERT_EQ(publish_d2(ctx, "qt.pkg.runtime", "1.0").get("accepted"), std::string("true"));
  const Msg activation = activate_d2(ctx, "qt.pkg.runtime", "DOWNLOAD_AND_CACHE");
  OS2_ASSERT(reply_from(activation).ok());
  OS2_ASSERT_EQ(reply_from(activation).current_state, std::string("deploying"));
  OS2_ASSERT_EQ(store.find("qt.pkg.runtime")->status, std::string("deploying"));
  OS2_ASSERT(store.rollout_log().empty());
  OS2_ASSERT_EQ(requests.size(), std::size_t{1});
  OS2_ASSERT_EQ(requests.back().get("fetch_required"), std::string("true"));

  ctx.buses.mgmt->publish(
      topics::ArtifactDeployReport,
      Msg{"ArtifactDeployReport", {{"deployment_id", activation.get("effective_value")},
                                    {"artifact_id", "qt.pkg.runtime"}, {"version", "1.0.0"},
                                    {"target_node", "wrong-node"}, {"instance_id", "svc-01"},
                                    {"stage", "running"}, {"observed_image_digest", kImageDigest},
                                    {"reporter", "service"}, {"timestamp", "1"}}});
  OS2_ASSERT_EQ(store.find("qt.pkg.runtime")->status, std::string("deploying"));
  report_running(ctx, activation, "qt.pkg.runtime", "1.0.0");
  OS2_ASSERT_EQ(store.find("qt.pkg.runtime")->status, std::string("activated"));
  OS2_ASSERT_EQ(store.rollout_log().size(), std::size_t{3});
  OS2_ASSERT_EQ(store.active_version("qt.pkg.runtime", "compute-01"), std::string("1.0.0"));
}

OS2_TEST(d2_rejects_overlapping_deployment_for_same_artifact_and_target) {
  std::vector<Msg> requests;
  ServiceContext ctx{BusPair::make_inproc(), d2_config()};
  ctx.buses.mgmt->serve(topics::PolicyCheck,
      [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
  ctx.buses.mgmt->serve(topics::ArtifactDeploy, [&](const Msg& m) {
    requests.push_back(m);
    return Msg{"ArtifactDeployReply", {{"accepted", "true"}, {"reason_code", errc::OK}}};
  });
  GrayscaleStore store{
      ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
  OS2_ASSERT(store.init() && store.start());
  publish_d2(ctx, "qt.pkg.serial", "1.0");
  publish_d2(ctx, "qt.pkg.serial", "2.0");

  const Msg first = activate_d2(ctx, "qt.pkg.serial", "DOWNLOAD_AND_CACHE", "activate", "1.0");
  OS2_ASSERT(reply_from(first).ok());
  const Msg overlapping =
      activate_d2(ctx, "qt.pkg.serial", "DOWNLOAD_AND_CACHE", "activate", "2.0");
  OS2_ASSERT(!reply_from(overlapping).ok());
  OS2_ASSERT_EQ(reply_from(overlapping).current_state, std::string("deployment-in-progress"));
  OS2_ASSERT_EQ(requests.size(), std::size_t{1});

  report_running(ctx, first, "qt.pkg.serial", "1.0.0");
  const Msg second = activate_d2(ctx, "qt.pkg.serial", "DOWNLOAD_AND_CACHE", "activate", "2.0");
  OS2_ASSERT(reply_from(second).ok());
  OS2_ASSERT_EQ(requests.size(), std::size_t{2});
}

OS2_TEST(d2_update_modes_produce_distinct_fetch_facts) {
  std::vector<Msg> requests;
  ServiceContext ctx{BusPair::make_inproc(), d2_config()};
  ctx.buses.mgmt->serve(topics::PolicyCheck,
      [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
  ctx.buses.mgmt->serve(topics::ArtifactDeploy, [&](const Msg& m) {
    requests.push_back(m);
    return Msg{"ArtifactDeployReply", {{"accepted", "true"}, {"reason_code", errc::OK}}};
  });
  GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
  OS2_ASSERT(store.init() && store.start());
  publish_d2(ctx, "qt.pkg.policy", "1.9");
  publish_d2(ctx, "qt.pkg.policy", "1.10");

  Msg first = activate_d2(ctx, "qt.pkg.policy", "DOWNLOAD_AND_CACHE");
  OS2_ASSERT_EQ(requests.back().get("version"), std::string("1.10.0"));
  OS2_ASSERT_EQ(requests.back().get("fetch_required"), std::string("true"));
  report_running(ctx, first, "qt.pkg.policy", "1.10.0");
  Msg cached = activate_d2(ctx, "qt.pkg.policy", "DOWNLOAD_AND_CACHE");
  OS2_ASSERT_EQ(requests.back().get("fetch_required"), std::string("false"));
  report_running(ctx, cached, "qt.pkg.policy", "1.10.0");
  OS2_ASSERT_EQ(store.fetch_count("qt.pkg.policy", "compute-01"), std::uint64_t{1});

  Msg always = activate_d2(ctx, "qt.pkg.policy", "ALWAYS_DOWNLOAD");
  OS2_ASSERT_EQ(requests.back().get("fetch_required"), std::string("true"));
  report_running(ctx, always, "qt.pkg.policy", "1.10.0");
  OS2_ASSERT_EQ(store.fetch_count("qt.pkg.policy", "compute-01"), std::uint64_t{2});

  Msg no_update = activate_d2(ctx, "qt.pkg.policy", "UPDATE_AND_CACHE");
  OS2_ASSERT_EQ(requests.back().get("fetch_required"), std::string("false"));
  report_running(ctx, no_update, "qt.pkg.policy", "1.10.0");
  publish_d2(ctx, "qt.pkg.policy", "1.11");
  Msg update = activate_d2(ctx, "qt.pkg.policy", "UPDATE_AND_CACHE");
  OS2_ASSERT_EQ(requests.back().get("version"), std::string("1.11.0"));
  OS2_ASSERT_EQ(requests.back().get("fetch_required"), std::string("true"));
  report_running(ctx, update, "qt.pkg.policy", "1.11.0");
  OS2_ASSERT_EQ(store.fetch_count("qt.pkg.policy", "compute-01"), std::uint64_t{3});

  Msg preloaded = activate_d2(ctx, "qt.pkg.policy", "PRELOADED");
  OS2_ASSERT_EQ(requests.back().get("fetch_required"), std::string("false"));
  OS2_ASSERT(requests.back().get("package_uri").empty());
  report_running(ctx, preloaded, "qt.pkg.policy", "1.11.0");
  OS2_ASSERT_EQ(store.fetch_count("qt.pkg.policy", "compute-01"), std::uint64_t{3});
}

OS2_TEST(d2_reject_timeout_and_digest_mismatch_never_activate) {
  {
    ServiceContext ctx{BusPair::make_inproc(), d2_config()};
    ctx.buses.mgmt->serve(topics::PolicyCheck,
        [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
    ctx.buses.mgmt->serve(topics::ArtifactDeploy, [](const Msg&) {
      return Msg{"ArtifactDeployReply", {{"accepted", "false"},
                                          {"reason_code", errc::WL_SPAWN_FAILED},
                                          {"reason", "backend unavailable"}}};
    });
    GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(store.init() && store.start());
    publish_d2(ctx, "qt.pkg.reject", "1.0");
    const Msg rejected = activate_d2(ctx, "qt.pkg.reject", "ALWAYS_DOWNLOAD");
    OS2_ASSERT(!reply_from(rejected).ok());
    OS2_ASSERT_EQ(store.find("qt.pkg.reject")->status, std::string("deployment-failed"));
    OS2_ASSERT(store.active_version("qt.pkg.reject", "compute-01").empty());
  }
  {
    Config cfg = d2_config();
    cfg.set("store.deploy_terminal_timeout_ms", "1");
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    ctx.buses.mgmt->serve(topics::PolicyCheck,
        [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
    ctx.buses.mgmt->serve(topics::ArtifactDeploy, [](const Msg&) {
      return Msg{"ArtifactDeployReply", {{"accepted", "true"}, {"reason_code", errc::OK}}};
    });
    GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(store.init() && store.start());
    publish_d2(ctx, "qt.pkg.timeout", "1.0");
    const Msg pending = activate_d2(ctx, "qt.pkg.timeout", "ALWAYS_DOWNLOAD");
    store.tick(now_ms() + 100);
    OS2_ASSERT_EQ(store.deployment_state(pending.get("effective_value")), std::string("timeout"));
    OS2_ASSERT_EQ(store.find("qt.pkg.timeout")->status, std::string("deployment-failed"));
  }
  {
    ServiceContext ctx{BusPair::make_inproc(), d2_config()};
    ctx.buses.mgmt->serve(topics::PolicyCheck,
        [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
    ctx.buses.mgmt->serve(topics::ArtifactDeploy, [](const Msg&) {
      return Msg{"ArtifactDeployReply", {{"accepted", "true"}, {"reason_code", errc::OK}}};
    });
    GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(store.init() && store.start());
    publish_d2(ctx, "qt.pkg.digest", "1.0");
    const Msg pending = activate_d2(ctx, "qt.pkg.digest", "ALWAYS_DOWNLOAD");
    report_running(ctx, pending, "qt.pkg.digest", "1.0.0", "sha256:" + std::string(64, 'c'));
    OS2_ASSERT_EQ(store.deployment_state(pending.get("effective_value")), std::string("failed"));
    OS2_ASSERT_EQ(store.find("qt.pkg.digest")->status, std::string("deployment-failed"));
    OS2_ASSERT(store.active_version("qt.pkg.digest", "compute-01").empty());
  }
}

OS2_TEST(d2_rollback_waits_for_previous_version_runtime_report) {
  ServiceContext ctx{BusPair::make_inproc(), d2_config()};
  ctx.buses.mgmt->serve(topics::PolicyCheck,
      [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
  ctx.buses.mgmt->serve(topics::ArtifactDeploy, [](const Msg&) {
    return Msg{"ArtifactDeployReply", {{"accepted", "true"}, {"reason_code", errc::OK}}};
  });
  GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
  OS2_ASSERT(store.init() && store.start());
  publish_d2(ctx, "qt.pkg.rollback", "1.0");
  Msg v1 = activate_d2(ctx, "qt.pkg.rollback", "DOWNLOAD_AND_CACHE");
  report_running(ctx, v1, "qt.pkg.rollback", "1.0.0");
  publish_d2(ctx, "qt.pkg.rollback", "2.0");
  Msg v2 = activate_d2(ctx, "qt.pkg.rollback", "UPDATE_AND_CACHE");
  report_running(ctx, v2, "qt.pkg.rollback", "2.0.0");
  OS2_ASSERT_EQ(store.active_version("qt.pkg.rollback", "compute-01"), std::string("2.0.0"));

  Msg rollback = activate_d2(ctx, "qt.pkg.rollback", "DOWNLOAD_AND_CACHE", "rollback");
  OS2_ASSERT(reply_from(rollback).ok());
  OS2_ASSERT_EQ(store.active_version("qt.pkg.rollback", "compute-01"), std::string("2.0.0"));
  OS2_ASSERT_EQ(store.find("qt.pkg.rollback", "1.0")->status, std::string("rolling-back"));
  report_running(ctx, rollback, "qt.pkg.rollback", "1.0.0");
  OS2_ASSERT_EQ(store.active_version("qt.pkg.rollback", "compute-01"), std::string("1.0.0"));
  OS2_ASSERT_EQ(store.find("qt.pkg.rollback", "1.0")->status, std::string("activated"));
  OS2_ASSERT_EQ(store.find("qt.pkg.rollback", "2.0")->status, std::string("rolled-back"));
}

OS2_TEST(d2_pending_deployment_is_restored_and_resent_idempotently) {
  const std::string path = "/tmp/os2_store_d2_resume.tsv";
  std::remove(path.c_str());
  std::string deployment_id;
  {
    ServiceContext ctx{BusPair::make_inproc(), d2_config(path)};
    ctx.buses.mgmt->serve(topics::PolicyCheck,
        [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
    ctx.buses.mgmt->serve(topics::ArtifactDeploy, [](const Msg&) {
      return Msg{"ArtifactDeployReply", {{"accepted", "true"}, {"reason_code", errc::OK}}};
    });
    GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(store.init() && store.start());
    publish_d2(ctx, "qt.pkg.resume", "1.0");
    Msg activation = activate_d2(ctx, "qt.pkg.resume", "ALWAYS_DOWNLOAD");
    deployment_id = activation.get("effective_value");
    store.stop();
  }
  std::vector<std::string> resumed;
  {
    ServiceContext ctx{BusPair::make_inproc(), d2_config(path)};
    ctx.buses.mgmt->serve(topics::ArtifactDeploy, [&](const Msg& m) {
      resumed.push_back(m.get("deployment_id"));
      return Msg{"ArtifactDeployReply", {{"accepted", "true"}, {"reason_code", errc::OK}}};
    });
    GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(store.init() && store.start());
    OS2_ASSERT_EQ(resumed.size(), std::size_t{1});
    OS2_ASSERT_EQ(resumed.front(), deployment_id);
    OS2_ASSERT_EQ(store.deployment_state(deployment_id), std::string("deploying"));
  }
  std::remove(path.c_str());
}

OS2_TEST(d2_staged_rollout_progress_survives_restart) {
  const std::string path = "/tmp/os2_store_d2_rollout_resume.tsv";
  std::remove(path.c_str());
  Config cfg = d2_config(path);
  cfg.set("store.rollout_mode", "staged");
  cfg.set("store.rollout_step_ms", "1000");
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    ctx.buses.mgmt->serve(topics::PolicyCheck,
        [](const Msg&) { return Msg{"D", {{"allow", "true"}}}; });
    ctx.buses.mgmt->serve(topics::ArtifactDeploy, [](const Msg&) {
      return Msg{"ArtifactDeployReply", {{"accepted", "true"}, {"reason_code", errc::OK}}};
    });
    GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(store.init() && store.start());
    publish_d2(ctx, "qt.pkg.rollout-resume", "1.0");
    Msg activation = activate_d2(ctx, "qt.pkg.rollout-resume", "DOWNLOAD_AND_CACHE");
    report_running(ctx, activation, "qt.pkg.rollout-resume", "1.0.0");
    OS2_ASSERT(store.rollout_in_flight());
    OS2_ASSERT_EQ(store.rollout_log().size(), std::size_t{1});
    store.stop();
  }
  {
    ServiceContext ctx{BusPair::make_inproc(), cfg};
    GrayscaleStore store{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "n", ""}, ctx};
    OS2_ASSERT(store.init() && store.start());
    OS2_ASSERT(store.rollout_in_flight());
    store.tick(now_ms() + 2000);
    OS2_ASSERT_EQ(store.rollout_log().size(), std::size_t{1});
    OS2_ASSERT(store.rollout_log().front().find("50%") != std::string::npos);
  }
  std::remove(path.c_str());
}
