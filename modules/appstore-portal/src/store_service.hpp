// =============================================================================
// store_service.hpp — 应用商店与门户框架类（Owner: @os2/owner-store）
//
// 框架已接线：ArtifactPublish（req/rep：校验→登记）、ActivationCommand
//             （req/rep：PolicyCheck→激活/回滚→审计留痕），回滚点记录。
// 开发者扩展点：make_verifier()（签名/SBOM/兼容矩阵）、on_activated()（灰度推进）。
// M1 任务卡方向：制品发布流水线、灰度策略、可视化门户、证据导出报表。
//
// 【阅读顺序】
//   1. on_init()：服务启动时把两个请求处理函数注册到管理总线。
//   2. handle_publish()：接收发布请求，校验成功后登记制品。
//   3. handle_activation()：执行激活或回滚，但操作前必须通过策略检查。
//   4. persist_state()/restore_state()：把内存状态保存到文件，并在重启后恢复。
//
// 【一条发布请求的调用链】
//   ArtifactPublish 消息
//        → handle_publish()
//        → verifier_->verify()
//        → artifacts_[artifact_id] = artifact
//        → ArtifactPublishReply
//
// 本文件只负责“商店服务的公共骨架”。更严格的 SHA-256、签名和真实文件接收
// 由派生类通过 make_verifier() 组合进来，避免把所有实现堆在一个类中。
// =============================================================================
#pragma once

// C/C++ 标准库依赖：文件读写、键值容器、智能指针、字符串和动态数组。
#include <cstdlib>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "os2/appstore_portal/api.hpp"
#include "os2/platform/atomic_file.hpp"
#include "os2/platform/platform.hpp"

namespace os2::store {

// -----------------------------------------------------------------------------
// DigestVerifier — 默认的最低限度校验器
// -----------------------------------------------------------------------------
// IArtifactVerifier 是统一校验接口。StoreService 不关心校验器内部怎样验证，
// 只调用 verify() 并接收 true/false 与失败原因。这是“策略模式”的简单应用。
//
// 默认实现仅保证 sha256 字段非空，适合框架最小运行。生产实现会在派生类中被
// Sha256FormatVerifier、签名校验器或 FilesystemArtifactVerifier 替换/包装。
class DigestVerifier : public IArtifactVerifier {
 public:
  // a：待发布的制品元数据；reason：失败时写入可返回给调用方的原因。
  bool verify(const Artifact& a, std::string& reason) override {
    if (a.sha256.empty()) { reason = "missing sha256"; return false; }
    return true;
  }
};

// -----------------------------------------------------------------------------
// StoreService — 应用商店服务的公共骨架
// -----------------------------------------------------------------------------
// 继承 Os2Service 后获得：生命周期、管理总线 mgmt()、配置 config() 和日志 log()。
// 本类再增加制品登记、激活/回滚以及状态持久化能力。
class StoreService : public Os2Service {
 public:
  // id 和 ctx 交给父类保存。std::move 表示转移对象内容，避免不必要的复制。
  StoreService(ServiceIdentity id, ServiceContext ctx)//构造函数，构造应用商店服务对象
      : Os2Service(std::move(id), std::move(ctx)) {}


  // 按制品 id 查询内存中的制品登记记录，返回制品副本
  // optional 表示“可能有结果，也可能没有”，调用方必须先检查 has_value()。
  std::optional<Artifact> find(const std::string& id) const {
    auto it = artifacts_.find(id);
    if (it == artifacts_.end()) return std::nullopt;
    return it->second;
  }

 protected://本类和子类可以调用，外部类不能调用
  // ---------------------------------------------------------------------------
  // 生命周期与扩展点
  // ---------------------------------------------------------------------------
  // init() 由 Os2Service 提供；init() 内部会回调这里的 on_init()。
  // 初始化阶段完成三件事：创建校验器、恢复状态、注册消息处理函数。
  bool on_init() override {//重写父类Os2Service服务的初始化操作

    // 虚函数调用允许派生类决定实际使用哪一种校验器。（目前有3个）
    verifier_ = make_verifier();//创建校验器

    // 恢复历史状态
    // 商店服务会把制品数据、激活版本持久化保存到数据库，服务启动时把制品数据加载回内存
    restore_state();  // F-07 D2：制品/激活态跨重启（灰度中断后可恢复）

    // serve(topic, handler) 表示：收到对应主题的请求时，同步调用 handler 并返回 Msg。
    // 告诉总线，如果收到这个主题的消息就交割对应函数处理
    // [this] 让 lambda 能访问当前 StoreService 对象；m 是收到的请求消息。
    // 注册 `ArtifactPublish` 处理器。
    mgmt().serve(topics::ArtifactPublish, [this](const Msg& m) { return handle_publish(m); });
    // 注册 `ActivationCommand` 处理器。
    mgmt().serve(topics::ActivationCommand, [this](const Msg& m) { return handle_activation(m); });
    return true;
  }

  // stop() 在停止时强制尝试保存一次，降低尚未到周期落盘时间就退出造成的数据丢失。
  void on_stop() override { persist_state(true); }

  // F-07（R0 §4-1 耐久等级 D2=尽力落盘，节拍聚合）：制品登记与激活态落盘——
  // store.persist_path 非空启用；缺省空=存量零变化。派生类 on_tick 需调本方法。
  void persist_tick(std::uint64_t now) {
    // 未到配置的落盘周期就直接返回，把多次状态变化合并成一次磁盘写入。
    if (now - last_persist_ms_ < config().get_u64("store.persist_ms", 1000)) return;//默认保存周期为 1000ms
    last_persist_ms_ = now;//更新 `last_persist_ms_`；保存成功时清除 `state_dirty_`
    persist_state(false);
  }

  // ---- 扩展点 ----
  // 派生类重写此函数即可换用更严格的校验链，StoreService 的发布流程无需修改。
  virtual std::unique_ptr<IArtifactVerifier> make_verifier() {
    return std::make_unique<DigestVerifier>();
  }
  // 制品状态改为 activated 后调用。基类不做额外操作，灰度商店在这里启动分批发布。
  // 灰度：分批、小范围试上线新版本
  virtual void on_activated(const Artifact&) {}  // 灰度推进钩子

 private:
  // ---------------------------------------------------------------------------
  // ArtifactPublish：接收并登记制品元数据
  // ---------------------------------------------------------------------------
  Msg handle_publish(const Msg& m) {
    // 从通用 Msg 的字段表中取值，组装成强类型 Artifact。
    // 新制品初始状态固定为 published，published_ms 记录当前发布时间。
    Artifact a{m.get("artifact_id"), m.get("version"), m.get("sha256"),
               m.get("sbom_ref"), "published", now_ms()};
    std::string reason;

    // 两级准入：artifact_id 必须存在，并且当前校验链必须全部通过。
    // verify() 失败时会填写 reason，调用方因此能知道拒绝原因。
    if (a.artifact_id.empty() || !verifier_->verify(a, reason))
      return Msg{"ArtifactPublishReply", {{"accepted", "false"}, {"reason", reason}}};

    // map 的 [] 会按 artifact_id 新增或覆盖记录。更严格的“同版本不可替换”保护
    // 位于 FilesystemArtifactVerifier：只有真实制品文件通过后才会走到这里。
    artifacts_[a.artifact_id] = a;

    // 只标记“状态已改变”，真正写盘由 persist_tick() 或 on_stop() 聚合执行。
    state_dirty_ = true;
    log().info("artifact_published", a.artifact_id + "@" + a.version);
    return Msg{"ArtifactPublishReply", {{"accepted", "true"}}};
  }

  // ---------------------------------------------------------------------------
  // ActivationCommand：激活或回滚已登记制品
  // ---------------------------------------------------------------------------
  Msg handle_activation(const Msg& m) {
    // 把通用消息解析为统一 Command；主要使用 target_id、command_type、operator_id。
    Command c = command_from(m);  // command_type: activate / rollback
    auto it = artifacts_.find(c.target_id);

    // 只能操作已经发布并登记的制品。Reply::failure 会带统一错误码与当前状态。
    if (it == artifacts_.end())
      return to_msg(Reply::failure(c, errc::SVC_NOT_REGISTERED, "unknown-artifact"));

    // 激活/回滚是高影响运维动作：必须过 PolicyCheck（《架构说明》§2.1 边界）
    // subject=谁操作，action=要做什么，target=操作谁，trace_id=全链路追踪号。
    Msg pc{"PolicyRequest", {{"subject", c.operator_id}, {"action", "artifact." + c.command_type},
                             {"target", c.target_id}, {"trace_id", c.trace_id}}};

    // 向策略服务发同步请求，最多等待 500ms。无响应和明确拒绝都按无权限处理。
    auto dec = mgmt().request(topics::PolicyCheck, pc, 500);
    if (!dec || dec->get("allow") != "true")
      return to_msg(Reply::failure(c, errc::SEC_DENIED, it->second.status));

    if (c.command_type == "activate") {
      // 若该制品原本已激活，则保留它作为回滚点；随后切换状态并触发灰度钩子。
      rollback_point_ = it->second.status == "activated" ? it->second.artifact_id : rollback_point_;
      it->second.status = "activated";
      on_activated(it->second);
    } else if (c.command_type == "rollback") {
      // 回滚在当前骨架中表现为状态切换；实际部署恢复可由更上层实现扩展。
      it->second.status = "rolled-back";
    } else {
      // 只接受 activate 和 rollback，其他命令类型属于非法操作链。
      return to_msg(Reply::failure(c, errc::SCH_CHAIN_INVALID, it->second.status));
    }

    state_dirty_ = true;
    log().info("artifact_" + c.command_type, c.target_id, c.trace_id);
    return to_msg(Reply::success(c, it->second.status));
  }

  // ---------------------------------------------------------------------------
  // 状态持久化：内存 → 文件
  // ---------------------------------------------------------------------------
  // F-07 D2 落盘：制品行 'A\t…6 字段' + 回滚点行 'R\t<id>'；原子替换写（无半文件）。
  void persist_state(bool force) {
    const std::string path = config().get("store.persist_path");

    // 未配置路径时关闭持久化；非强制模式下，没有修改也不重复写盘。
    if (path.empty() || (!state_dirty_ && !force)) return;
    std::string body;

    // 每个制品写成一行 TSV：
    // A、id、版本、摘要、SBOM、状态、发布时间。\t 是列分隔符，\n 是行结束符。
    for (auto& [id, a] : artifacts_)
      body += "A\t" + a.artifact_id + '\t' + a.version + '\t' + a.sha256 + '\t' +
              a.sbom_ref + '\t' + a.status + '\t' + std::to_string(a.published_ms) + '\n';

    // R 行单独保存回滚点，便于 restore_state() 按首列区分记录类型。
    if (!rollback_point_.empty()) body += "R\t" + rollback_point_ + '\n';

    // atomic_write 先写临时文件再原子替换目标文件，避免异常中断留下半个状态文件。
    if (!os2::fsio::atomic_write(path, body)) {
      log().warn("store_persist_failed", "cannot write " + path);
      return;
    }

    // 只有确认写入成功，才能清除脏标记；失败时保留 true，下一周期还会重试。
    state_dirty_ = false;
  }

  // ---------------------------------------------------------------------------
  // 状态恢复：文件 → 内存
  // ---------------------------------------------------------------------------
  void restore_state() {
    const std::string path = config().get("store.persist_path");
    if (path.empty()) return;
    std::ifstream f(path);

    // 首次运行时文件可能不存在，这不是故障，按空商店继续启动。
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
      std::vector<std::string> c;

      // 手工按制表符拆分一行。i 是当前字段起点，q 是下一个分隔符位置。
      // 找不到分隔符时令 q 等于行尾，从而把最后一个字段也加入 c。
      for (std::size_t i = 0, q; i <= line.size(); i = q + 1) {
        q = line.find('\t', i);
        if (q == std::string::npos) q = line.size();
        c.push_back(line.substr(i, q - i));
        if (q == line.size()) break;
      }

      // R 行恰好两列；A 行恰好七列。列数不符的损坏行会被忽略，不让服务崩溃。
      if (c.size() == 2 && c[0] == "R") {
        rollback_point_ = c[1];
      } else if (c.size() == 7 && c[0] == "A") {
        // strtoull 把文件中的十进制时间字符串恢复为 uint64_t。
        artifacts_[c[1]] = Artifact{c[1], c[2], c[3], c[4], c[5],
                                    std::strtoull(c[6].c_str(), nullptr, 10)};
      }
    }
    if (!artifacts_.empty())
      log().info("store_restored", std::to_string(artifacts_.size()) + " artifacts from " + path);
  }

  // verifier_：当前发布准入校验链；unique_ptr 表示由 StoreService 独占其生命周期。
  std::unique_ptr<IArtifactVerifier> verifier_;
  // artifacts_：内存制品目录，键是 artifact_id，值是完整制品元数据。
  std::map<std::string, Artifact> artifacts_;
  // rollback_point_：最近记录的回滚目标 id。
  std::string rollback_point_;
  // state_dirty_：内存是否发生过尚未持久化的修改。
  bool state_dirty_{false};
  // last_persist_ms_：上次周期落盘时刻，用于限制写盘频率。
  std::uint64_t last_persist_ms_{0};
};

}  // namespace os2::store
