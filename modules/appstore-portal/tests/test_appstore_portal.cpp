#include "store_service.hpp"
#include "os2/platform/testing.hpp"

using namespace os2;
using namespace os2::store;

OS2_TEST(publish_activate_rollback_with_policy) {
  ServiceContext ctx{BusPair::make_inproc(), Config{}};
  ctx.buses.mgmt->serve(topics::PolicyCheck,
      [](const Msg&) { return Msg{"PolicyDecision", {{"allow", "true"}}}; });
  StoreService s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "hmi-01", ""}, ctx};
  OS2_ASSERT(s.init() && s.start());

  // 无摘要 → 拒绝
  auto bad = ctx.buses.mgmt->request(topics::ArtifactPublish,
      Msg{"ArtifactPublish", {{"artifact_id", "app-x"}, {"version", "1.0"}}}, 100);
  OS2_ASSERT(bad && bad->get("accepted") == "false");

  auto ok = ctx.buses.mgmt->request(topics::ArtifactPublish,
      Msg{"ArtifactPublish", {{"artifact_id", "app-x"}, {"version", "1.0"},
                              {"sha256", "abc123"}}}, 100);
  OS2_ASSERT(ok && ok->get("accepted") == "true");

  Command act{gen_id("cmd"), "app-x", "activate", "{}", "release-mgr", "ctx", 0, "t-act"};
  auto r1 = ctx.buses.mgmt->request(topics::ActivationCommand, to_msg(act), 100);
  OS2_ASSERT(r1 && reply_from(*r1).ok());
  OS2_ASSERT_EQ(s.find("app-x")->status, std::string("activated"));

  Command rb{gen_id("cmd"), "app-x", "rollback", "{}", "release-mgr", "ctx", 0, "t-rb"};
  auto r2 = ctx.buses.mgmt->request(topics::ActivationCommand, to_msg(rb), 100);
  OS2_ASSERT(r2 && reply_from(*r2).ok());
  OS2_ASSERT_EQ(s.find("app-x")->status, std::string("rolled-back"));
}

OS2_TEST(activation_denied_without_policy) {
  ServiceContext ctx{BusPair::make_inproc(), Config{}};  // 无 PolicyCheck 应答方 → 从严拒绝
  StoreService s{ServiceIdentity{"os2.core.appstore-portal", "0.1.0", Domain::Hmi, "hmi-01", ""}, ctx};
  OS2_ASSERT(s.init() && s.start());
  ctx.buses.mgmt->request(topics::ArtifactPublish,
      Msg{"ArtifactPublish", {{"artifact_id", "app-y"}, {"version", "1"}, {"sha256", "z"}}}, 100);
  Command act{gen_id("cmd"), "app-y", "activate", "{}", "someone", "ctx", 0, "t"};
  auto r = ctx.buses.mgmt->request(topics::ActivationCommand, to_msg(act), 100);
  OS2_ASSERT(r && !reply_from(*r).ok());
  OS2_ASSERT_EQ(reply_from(*r).reason_code, std::string(errc::SEC_DENIED));
}

int main() { return os2::testing::run_all(); }
