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
    OS2_ASSERT_EQ(a->version, std::string("1.0"));
    OS2_ASSERT_EQ(a->sbom_ref, std::string("sbom://1"));
  }
  std::remove(path.c_str());
}
