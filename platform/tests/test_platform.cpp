// platform 框架自测：总线、契约映射、生命周期、服务链解析、实例寻址、X.509 解析。
#include <dirent.h>
#include <sys/stat.h>

#include <fstream>
#include <map>

#include "os2/platform/addressing.hpp"
#include "os2/platform/hash.hpp"
#include "os2/platform/msg_validator.hpp"
#include "os2/platform/platform.hpp"
#include "os2/platform/testing.hpp"
#include "os2/platform/x509.hpp"

using namespace os2;

// ---- X509 方案 ①（选项 B）：最小 ASN.1 解析真逻辑 ----
// 夹具：openssl 生成的自签 EC 证书（CN=os2-test-fixture，2026-01-01~2036-01-01 UTC）
static const char* kFixturePem = R"(-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUfLT4ZS0Ue2MNiw1REbizvtff1T8wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQb3MyLXRlc3QtZml4dHVyZTAeFw0yNjAxMDEwMDAwMDBaFw0z
NjAxMDEwMDAwMDBaMBsxGTAXBgNVBAMMEG9zMi10ZXN0LWZpeHR1cmUwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATGLaD+FUnsZxdy2uS7Fene/1iPiszshaujoMGW
D39UmXK/HyXhZkBc6A2Alro72s4QRyn2sf2TP9mdmRJwk8ZCo1MwUTAdBgNVHQ4E
FgQUREm9FqJMupddPcV4tzOtXe+IAS0wHwYDVR0jBBgwFoAUREm9FqJMupddPcV4
tzOtXe+IAS0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA2QbY
2gxsYmtgMt27a/bTWeaBFl/CjN5yi7P2aO92JUACIC8ZJZDP7MI8jHMHyKSLg9rO
CHV63st7sOr8d2Te2cOZ
-----END CERTIFICATE-----
)";

OS2_TEST(x509_parse_pem_extracts_cn_validity_algo) {
  auto info = x509::parse_pem_info(kFixturePem);
  OS2_ASSERT(info.parsed);
  OS2_ASSERT_EQ(info.subject_cn, std::string("os2-test-fixture"));
  OS2_ASSERT_EQ(info.issuer_cn, std::string("os2-test-fixture"));   // 自签：issuer=subject
  OS2_ASSERT_EQ(info.not_before_s, 1767225600ULL);   // 2026-01-01T00:00:00Z
  OS2_ASSERT_EQ(info.not_after_s, 2082758400ULL);    // 2036-01-01T00:00:00Z
  OS2_ASSERT_EQ(info.pubkey_algo, std::string("ecdsa"));
  OS2_ASSERT(x509::valid_at(info, 1767225600ULL));       // 窗内（下界含）
  OS2_ASSERT(x509::valid_at(info, 1900000000ULL));       // 窗内
  OS2_ASSERT(!x509::valid_at(info, 1767225599ULL));      // 生效前拒
  OS2_ASSERT(!x509::valid_at(info, 2082758401ULL));      // 过期拒
}

OS2_TEST(x509_parse_rejects_garbage_without_partial_result) {
  OS2_ASSERT(!x509::parse_pem_info("not a pem at all").parsed);
  OS2_ASSERT(!x509::parse_pem_info("-----BEGIN CERTIFICATE-----\nAAAA\n"
                                   "-----END CERTIFICATE-----\n").parsed);
  std::string truncated{kFixturePem};
  truncated = truncated.substr(0, 200) + "\n-----END CERTIFICATE-----\n";
  OS2_ASSERT(!x509::parse_pem_info(truncated).parsed);   // 截断 DER：越界即整体失败
}

OS2_TEST(x509_testvector_backend_allowlist_only) {
  x509::TestVectorBackend b{{{"deadbeef", "cafe01"}}};
  std::string why;
  OS2_ASSERT(b.verify("deadbeef", "cafe01", "", "", why));    // 向量命中
  OS2_ASSERT(!b.verify("deadbeef", "cafe02", "", "", why));   // 签名不符拒
  OS2_ASSERT(why.find("testvec") == 0);
  OS2_ASSERT(!b.verify("feedface", "cafe01", "", "", why));   // 未知摘要拒
}

OS2_TEST(x509_spawn_backend_materializes_and_cleans) {
  const std::string dir = "/tmp/os2_x509_spawn_test";
  ::mkdir(dir.c_str(), 0777);
  // 假脚本：断言收到 4 个实参且签名文件确实落盘，然后放行
  const std::string ok_script = dir + "/ok.sh";
  { std::ofstream s(ok_script); s << "#!/bin/sh\n[ $# -eq 4 ] || exit 64\n[ -s \"$2\" ] || exit 65\nexit 0\n"; }
  const std::string deny_script = dir + "/deny.sh";
  { std::ofstream s(deny_script); s << "#!/bin/sh\nexit 3\n"; }
  std::string why;
  x509::SpawnScriptBackend ok{ok_script, dir};
  OS2_ASSERT(ok.verify("deadbeef", "cafe01", "PEM1", "PEM2", why));
  x509::SpawnScriptBackend deny{deny_script, dir};
  OS2_ASSERT(!deny.verify("deadbeef", "cafe01", "PEM1", "PEM2", why));
  OS2_ASSERT(why.find("signature verify failed") != std::string::npos);
  OS2_ASSERT(!deny.verify("deadbeef", "zz", "p", "c", why));  // 非法 hex：不落盘直接拒
  // 材料用毕即删：目录里不残留 os2x5-* 临时件
  DIR* d = ::opendir(dir.c_str());
  OS2_ASSERT(d != nullptr);
  int leftovers = 0;
  while (auto* ent = ::readdir(d))
    if (std::string(ent->d_name).rfind("os2x5-", 0) == 0) ++leftovers;
  ::closedir(d);
  OS2_ASSERT_EQ(leftovers, 0);
}

// ---- R2-⑤/F-04 实例寻址接收侧校验：落位=执行约束非解释字段 ----
OS2_TEST(addressed_serve_rejects_misrouted_and_stamps_served_by) {
  InProcBus bus(BusPlane::Business);
  int executed = 0;
  bus.serve("os2.biz.svc.x", addressing::addressed("pod2", [&](const Msg& m) {
    ++executed;
    return Msg{"R", {{"result", "success"}, {"trace_id", m.get("trace_id")}}};
  }));
  // 定向错实例：拒收 + 业务逻辑零执行 + 自证 served_by
  auto mis = bus.request("os2.biz.svc.x",
                         Msg{"I", {{"node", "pod1"}, {"trace_id", "t1"}}}, 100);
  OS2_ASSERT(mis && mis->get("result") == std::string("failed"));
  OS2_ASSERT(mis->get("reason").find("misrouted") == 0);
  OS2_ASSERT_EQ(mis->get("served_by"), std::string("pod2"));
  OS2_ASSERT_EQ(executed, 0);
  // 定向本实例：执行 + 盖章
  auto ok = bus.request("os2.biz.svc.x", Msg{"I", {{"node", "pod2"}}}, 100);
  OS2_ASSERT(ok && ok->get("result") == std::string("success"));
  OS2_ASSERT_EQ(ok->get("served_by"), std::string("pod2"));
  OS2_ASSERT_EQ(executed, 1);
  // 不定向（无 node）：兼容存量，照常执行
  auto any = bus.request("os2.biz.svc.x", Msg{"I", {}}, 100);
  OS2_ASSERT(any && any->get("result") == std::string("success"));
  OS2_ASSERT_EQ(executed, 2);
}

OS2_TEST(bus_pub_sub_delivers) {
  InProcBus bus(BusPlane::Management);
  int hits = 0;
  bus.subscribe("t", [&](const Msg& m) { hits += m.get("n") == "1"; });
  bus.subscribe("t", [&](const Msg&) { ++hits; });
  bus.publish("t", Msg{"X", {{"n", "1"}}});
  OS2_ASSERT_EQ(hits, 2);
}

OS2_TEST(bus_request_reply_and_timeout) {
  InProcBus bus(BusPlane::Management);
  OS2_ASSERT(!bus.request("none", Msg{}, 10).has_value());  // 无应答方
  bus.serve("echo", [](const Msg& m) { return Msg{"R", {{"v", m.get("v")}}}; });
  auto rep = bus.request("echo", Msg{"Q", {{"v", "42"}}}, 10);
  OS2_ASSERT(rep && rep->get("v") == "42");
}

OS2_TEST(contract_roundtrip_command_reply) {
  Command c{"cmd-1", "dev-1", "reset", "{}", "op-1", "ctx", 3000, "trace-1"};
  Command c2 = command_from(to_msg(c));
  OS2_ASSERT_EQ(c2.command_id, c.command_id);
  OS2_ASSERT_EQ(c2.operator_id, c.operator_id);
  OS2_ASSERT_EQ(c2.deadline_ms, c.deadline_ms);
  Reply r = Reply::success(c, "RUNNING");
  Reply r2 = reply_from(to_msg(r));
  OS2_ASSERT(r2.ok());
  OS2_ASSERT_EQ(r2.trace_id, std::string("trace-1"));
  OS2_ASSERT_EQ(r2.reason_code, std::string(errc::OK));
}

namespace {
class DummyService : public Os2Service {
 public:
  using Os2Service::Os2Service;
  int ticks = 0;
 protected:
  void on_tick(std::uint64_t) override { ++ticks; }
};
}  // namespace

OS2_TEST(service_lifecycle_degrades_without_registry) {
  ServiceContext ctx{BusPair::make_inproc(), Config{}};
  DummyService s{ServiceIdentity{"os2.test.dummy", "0.1.0", Domain::Compute, "n1", ""}, ctx};
  OS2_ASSERT(s.init());
  OS2_ASSERT(s.start());  // 注册中心不在 → 降级启动，不阻塞
  OS2_ASSERT(s.state() == ServiceState::DegradedState);
  s.tick(now_ms() + 2000);
  OS2_ASSERT_EQ(s.ticks, 1);
  s.stop();
  OS2_ASSERT(s.state() == ServiceState::Stopped);
}

OS2_TEST(service_registers_when_registry_present) {
  ServiceContext ctx{BusPair::make_inproc(), Config{}};
  ctx.buses.mgmt->serve(topics::ServiceRegister,
                        [](const Msg&) { return Msg{"ServiceRegisterReply", {{"accepted", "true"}}}; });
  DummyService s{ServiceIdentity{"os2.test.dummy", "0.1.0", Domain::Compute, "n1", ""}, ctx};
  OS2_ASSERT(s.init() && s.start());
  OS2_ASSERT(s.state() == ServiceState::Running);
}

OS2_TEST(service_rejoins_after_registry_appears) {  // M0.9/ADR-0008：降级 → rejoin 收敛
  ServiceContext ctx{BusPair::make_inproc(), Config{}};
  DummyService s{ServiceIdentity{"os2.test.dummy", "0.1.0", Domain::Compute, "n1", ""}, ctx};
  OS2_ASSERT(s.init() && s.start());
  OS2_ASSERT(s.state() == ServiceState::DegradedState);  // 注册中心尚不存在

  int registrations = 0;
  ctx.buses.mgmt->serve(topics::ServiceRegister, [&](const Msg&) {  // 注册中心"上线"
    ++registrations;
    return Msg{"ServiceRegisterReply", {{"accepted", "true"}, {"epoch", "e1"}}};
  });
  std::uint64_t clk = now_ms();
  s.tick(clk + 4000);  // 超过 service.rejoin_ms 缺省 3000 → 自动重注册
  OS2_ASSERT(registrations >= 1);
  OS2_ASSERT(s.state() == ServiceState::Running);
}

OS2_TEST(service_reregisters_on_registry_epoch_change) {  // 注册中心重启 → 纪元换 → 全员重注册
  ServiceContext ctx{BusPair::make_inproc(), Config{}};
  int registrations = 0;
  std::string epoch = "e1";
  ctx.buses.mgmt->serve(topics::ServiceRegister, [&](const Msg&) {
    ++registrations;
    return Msg{"ServiceRegisterReply", {{"accepted", "true"}, {"epoch", epoch}}};
  });
  DummyService s{ServiceIdentity{"os2.test.dummy", "0.1.0", Domain::Compute, "n1", ""}, ctx};
  OS2_ASSERT(s.init() && s.start());
  OS2_ASSERT_EQ(registrations, 1);

  ctx.buses.mgmt->publish(topics::RegistryAnnounce, Msg{"RegistryAnnounce", {{"epoch", "e1"}}});
  OS2_ASSERT_EQ(registrations, 1);  // 纪元未变 → 不重注册

  epoch = "e2";  // 模拟注册中心重启（目录清空、新纪元）
  ctx.buses.mgmt->publish(topics::RegistryAnnounce, Msg{"RegistryAnnounce", {{"epoch", "e2"}}});
  OS2_ASSERT_EQ(registrations, 2);  // 纪元变化 → 立即重注册
  ctx.buses.mgmt->publish(topics::RegistryAnnounce, Msg{"RegistryAnnounce", {{"epoch", "e2"}}});
  OS2_ASSERT_EQ(registrations, 2);  // 幂等
}

// 注册着也要周期重申——"目录里还有没有我"，本进程从自己这边看不出来。
// 实缺陷（2026-08-19 现场，负责人拔 cai-01 网线再插回）：断开期间租约到期，
// 注册中心把记录判 down 并回收；插回后**节点画像与进程自报都自己恢复了**
// （那两条本来就是周期上报），唯独服务注册没有——目录里从此没有它，
// 链步派不下去，报 OS2-3001。纪元广播那条收敛也不触发：注册中心没重启、纪元没变。
OS2_TEST(service_reasserts_registration_periodically) {
  ServiceContext ctx{BusPair::make_inproc(), Config{}};
  int registrations = 0;
  ctx.buses.mgmt->serve(topics::ServiceRegister, [&](const Msg&) {
    ++registrations;
    return Msg{"ServiceRegisterReply", {{"accepted", "true"}, {"epoch", "e1"}}};
  });
  DummyService s{ServiceIdentity{"os2.test.dummy", "0.1.0", Domain::Compute, "n1", ""}, ctx};
  OS2_ASSERT(s.init() && s.start());
  OS2_ASSERT_EQ(registrations, 1);

  const std::uint64_t t0 = now_ms();
  s.tick(t0 + 1000);                    // 不到重申周期（缺省 5000）
  OS2_ASSERT_EQ(registrations, 1);
  s.tick(t0 + 6000);                    // 过了 → 重申一次
  OS2_ASSERT_EQ(registrations, 2);
  s.tick(t0 + 12000);                   // 再过一个周期 → 再重申
  OS2_ASSERT_EQ(registrations, 3);
  OS2_ASSERT(s.state() == ServiceState::Running);  // 重申不改变状态
}

OS2_TEST(chain_parse_and_topo) {
  const char* xml = R"(<?xml version="1.0"?>
    <ServiceChain id="c1" deadline_ms="200">
      <Node id="n2" service="b.s" criticality="A"/>
      <Node id="n1" service="a.s" criticality="B"/>
      <Edge from="n1" to="n2"/>
    </ServiceChain>)";
  auto c = parse_sc_xml(xml);
  OS2_ASSERT(c.has_value());
  OS2_ASSERT_EQ(c->deadline_ms, 200u);
  OS2_ASSERT(!c->validate().has_value());
  auto order = c->topo_order();
  OS2_ASSERT(order && order->size() == 2 && (*order)[0].id == "n1");
}

OS2_TEST(chain_cycle_rejected) {
  ServiceChain c;
  c.id = "bad";
  c.nodes = {{"a", "x", Criticality::A}, {"b", "y", Criticality::A}};
  c.edges = {{"a", "b"}, {"b", "a"}};
  OS2_ASSERT(c.validate().has_value());
}

// ---- RFC-0005：消息边界校验器 MsgValidator（运行时类型化/尺寸/失败拒收）----
static Msg good_control() {  // 合规 ProgramControlCommand.req（三必填齐）
  return Msg{"Command", {{"command_id", "cmd-1"}, {"target_id", "dev-1"},
                         {"command_type", "start"}}};
}

OS2_TEST(msgv_number_key_rejects_nonnumeric_and_accepts_numeric) {
  auto v = msgv::MsgValidator::for_topic("ProgramControlCommand", "req", {});
  OS2_ASSERT(v.has_spec());
  Msg bad = good_control();
  bad.kv["deadline_ms"] = "abc";  // number 键非数值 → 拒（旧 get_u64 会静默 0）
  auto r = v.check(bad);
  OS2_ASSERT(r.has_value());
  OS2_ASSERT_EQ(std::string(r->code), std::string(errc::MSG_TYPE_REJECTED));
  Msg okm = good_control();
  okm.kv["deadline_ms"] = "1500";  // 数值 → 过
  OS2_ASSERT(!v.check(okm).has_value());
  Msg partial = good_control();
  partial.kv["deadline_ms"] = "15x";  // 部分消费 → 拒
  OS2_ASSERT(v.check(partial).has_value());
}

OS2_TEST(msgv_missing_required_rejected_opt_missing_ok) {
  auto v = msgv::MsgValidator::for_topic("ProgramControlCommand", "req", {});
  Msg miss = good_control();
  miss.kv.erase("command_id");  // 必填缺失 → 拒
  auto r = v.check(miss);
  OS2_ASSERT(r.has_value());
  OS2_ASSERT_EQ(std::string(r->code), std::string(errc::MSG_TYPE_REJECTED));
  OS2_ASSERT(!v.check(good_control()).has_value());  // 仅三必填、opt 全缺 → 过
}

OS2_TEST(msgv_enum_key_rejects_bad_token) {
  auto v = msgv::MsgValidator::for_topic("ResourceReport", "pub", {});
  Msg m{"ResourceReport", {{"node_id", "n1"}, {"domain", "compute"}, {"cpu_total", "8"},
        {"cpu_used", "2"}, {"mem_total_mib", "1024"}, {"mem_used_mib", "256"},
        {"os", "Linux"}, {"health", "ok"}, {"ts", "100"}, {"container_id", "c1"},
        {"boot_state", "up"}, {"modules", "a,b"}, {"payload", "p"}}};
  OS2_ASSERT(!v.check(m).has_value());     // 合规
  m.kv["domain"] = "xyz";                  // 非法枚举 token → 拒
  OS2_ASSERT(v.check(m).has_value());
  m.kv["domain"] = "compute";
  m.kv["health"] = "melted";               // 非法枚举 token → 拒
  OS2_ASSERT(v.check(m).has_value());
}

OS2_TEST(msgv_pattern_number_key_prefix_checked) {  // score.<node> 为 number+pattern
  auto v = msgv::MsgValidator::for_topic("ResourceInventoryQuery", "rep", {});
  Msg m{"ResourceInventoryQuery", {{"node_ids", "n1,n2"}, {"score.n1", "0.5"}}};
  OS2_ASSERT(!v.check(m).has_value());
  m.kv["score.n2"] = "notnum";             // 动态 number 键非数值 → 拒
  auto r = v.check(m);
  OS2_ASSERT(r.has_value());
  OS2_ASSERT_EQ(std::string(r->code), std::string(errc::MSG_TYPE_REJECTED));
}

OS2_TEST(msgv_size_gates) {
  msgv::SizeLimits lim;
  lim.max_fields = 3;
  auto vf = msgv::MsgValidator::for_topic("ProgramControlCommand", "req", lim);
  Msg m = good_control();
  m.kv["deadline_ms"] = "1";  // 4 键 > 3 → 尺寸拒
  auto r = vf.check(m);
  OS2_ASSERT(r.has_value());
  OS2_ASSERT_EQ(std::string(r->code), std::string(errc::MSG_SIZE_EXCEEDED));

  msgv::SizeLimits lv;
  lv.max_value_len = 4;
  auto vv = msgv::MsgValidator::for_topic("ProgramControlCommand", "req", lv);
  Msg m2 = good_control();
  m2.kv["command_type"] = "reset";  // len 5 > 4 → 尺寸拒
  OS2_ASSERT_EQ(std::string(vv.check(m2)->code), std::string(errc::MSG_SIZE_EXCEEDED));

  msgv::SizeLimits lb;
  lb.max_msg_bytes = 8;
  auto vb = msgv::MsgValidator::for_topic("ProgramControlCommand", "req", lb);
  OS2_ASSERT_EQ(std::string(vb.check(good_control())->code),
                std::string(errc::MSG_SIZE_EXCEEDED));
}

OS2_TEST(msgv_strict_accessors_optional_semantics) {
  Msg m{"X", {{"a", "12"}, {"b", "abc"}, {"c", ""}, {"d", "3.5"}, {"e", "9x"}}};
  OS2_ASSERT(m.get_u64_checked("a").value() == 12u);
  OS2_ASSERT(!m.get_u64_checked("b").has_value());   // 非数值
  OS2_ASSERT(!m.get_u64_checked("c").has_value());   // 空
  OS2_ASSERT(!m.get_u64_checked("z").has_value());   // 缺失
  OS2_ASSERT(!m.get_u64_checked("e").has_value());   // 部分消费
  OS2_ASSERT(m.get_num_checked("d").value() == 3.5);
  OS2_ASSERT(!m.get_num_checked("b").has_value());
  OS2_ASSERT_EQ(m.get_u64("b"), 0u);                 // 宽松版仍静默 0（存量不变）
}

OS2_TEST(msgv_validate_enabled_csv_parsing) {
  Config c1(std::map<std::string, std::string>{
      {"bus.validate", "A, ProgramControlCommand ,B"}});
  OS2_ASSERT(msgv::validate_enabled(c1, "ProgramControlCommand"));  // 含空白仍命中
  OS2_ASSERT(!msgv::validate_enabled(c1, "C"));
  Config c2(std::map<std::string, std::string>{{"bus.validate", "*"}});
  OS2_ASSERT(msgv::validate_enabled(c2, "AnyTopic"));               // 通配
  Config c3;
  OS2_ASSERT(!msgv::validate_enabled(c3, "ProgramControlCommand")); // 缺省关
}

OS2_TEST(service_chain_formal_msgspec_positive_truncation_and_wrong_type) {
  auto submit_req = msgv::MsgValidator::for_topic("ServiceChainSubmit", "req", {});
  auto submit_rep = msgv::MsgValidator::for_topic("ServiceChainSubmit", "rep", {});
  auto step = msgv::MsgValidator::for_topic("ChainStepEvent", "pub", {});
  auto feedback = msgv::MsgValidator::for_topic("ExecutionFeedback", "pub", {});
  OS2_ASSERT(submit_req.has_spec() && submit_rep.has_spec() &&
             step.has_spec() && feedback.has_spec());

  Msg req{"ChainSubmit", {{"sc_xml", "<ServiceChain id=\"c\"/>"}}};
  OS2_ASSERT(!submit_req.check(req).has_value());
  req.kv.erase("sc_xml");
  OS2_ASSERT_EQ(std::string(submit_req.check(req)->code),
                std::string(errc::MSG_TYPE_REJECTED));

  Msg rep{"ChainSubmitReply",
          {{"chain_id", "c"}, {"trace_id", "t"}, {"success", "true"},
           {"reason_code", errc::OK}, {"cost_ms", "1"}}};
  OS2_ASSERT(!submit_rep.check(rep).has_value());
  rep.kv["success"] = "yes";
  OS2_ASSERT_EQ(std::string(submit_rep.check(rep)->code),
                std::string(errc::MSG_TYPE_REJECTED));

  Msg ev{"ChainStepEvent",
         {{"chain_id", "c"}, {"trace_id", "t"}, {"seq", "1"}, {"total", "1"},
          {"chain_node_id", "n"}, {"service", "q32.echo"},
          {"assigned_node", "node"}, {"criticality", "C"},
          {"state", "running"}, {"reason_code", errc::OK}, {"ts", "1"}}};
  OS2_ASSERT_EQ(std::string(step.check(ev)->code),
                std::string(errc::MSG_TYPE_REJECTED));

  Msg fb{"ExecutionFeedback",
         {{"chain_id", "c"}, {"trace_id", "t"}, {"success", "true"},
          {"reason_code", errc::OK}, {"cost_ms", "not-a-number"},
          {"completed_nodes", "n"}}};
  OS2_ASSERT_EQ(std::string(feedback.check(fb)->code),
                std::string(errc::MSG_TYPE_REJECTED));
}

OS2_TEST(sha256_stream_matches_one_shot_across_chunk_boundaries) {
  const std::string content = std::string(63, 'a') + "bc" + std::string(4097, 'z');
  hash::Sha256Stream stream;
  stream.update(content.data(), 1);
  stream.update(content.data() + 1, 63);
  stream.update(content.data() + 64, content.size() - 64);
  OS2_ASSERT_EQ(hash::hex(stream.finalize()), hash::sha256_hex(content));
  OS2_ASSERT_EQ(hash::sha256_hex("abc"),
                std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

int main() { return os2::testing::run_all(); }
