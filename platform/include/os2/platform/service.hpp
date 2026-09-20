// =============================================================================
// os2/platform/service.hpp — 服务框架基类 Os2Service（所有 9 大模块的父类）
//
// 架构依据：
//   * 生命周期状态机与注册/心跳：《架构说明》§8.4 启动拉起顺序、§8.7 接口清单。
//   * 服务上下文：模块只能拿到 双总线 + 配置 + 日志 + 身份 —— 不提供越界访问。
//
// 执行模型（M0.5 架构决策，见 docs/FRAMEWORK.md §3）：
//   单线程协作式。运行器循环调用 tick(now_ms)；总线回调同步派发。
//   并发与真实传输属 comm-middleware-pal / 集成部署的 M1 任务，不在模块代码中出现。
//
// 开发者边界：
//   * 继承本类的模块框架类由架构师给出（modules/<m>/src/*_service.hpp）。
//   * 模块开发者只实现框架类暴露的 protected 虚扩展点，不改本文件。
// =============================================================================
#pragma once

#include <memory>
#include <string>

#include "os2/platform/bus.hpp"
#include "os2/platform/config.hpp"
#include "os2/platform/contracts.hpp"
#include "os2/platform/log.hpp"

namespace os2 {

// 生命周期状态机（服务目录/门户可见；对齐服务治理"生命周期事件"口径）
enum class ServiceState { Created, Initialized, Registered, Running, DegradedState, Stopped };

inline const char* to_string(ServiceState s) {
  switch (s) {
    case ServiceState::Created: return "created";
    case ServiceState::Initialized: return "initialized";
    case ServiceState::Registered: return "registered";
    case ServiceState::Running: return "running";
    case ServiceState::DegradedState: return "degraded";
    default: return "stopped";
  }
}

// 服务身份与上下文 —— 框架注入，模块只读
struct ServiceIdentity {
  std::string service_id;   // 如 os2.core.scheduler
  std::string version;      // 如 0.1.0
  Domain domain{Domain::Compute};
  std::string node_id;      // 部署节点
  std::string instance_id;  // 实例 ID（框架生成）
};

struct ServiceContext {
  BusPair buses;
  Config config;
};

// -----------------------------------------------------------------------------
// Os2Service — 框架基类
// -----------------------------------------------------------------------------
class Os2Service {
 public:
  Os2Service(ServiceIdentity id, ServiceContext ctx)
      : id_(std::move(id)), ctx_(std::move(ctx)) {
    if (id_.instance_id.empty()) id_.instance_id = gen_id("inst");
    logger_ = Logger(id_.service_id, id_.instance_id, to_string(id_.domain), id_.node_id);
  }
  virtual ~Os2Service() = default;

  // ---- 生命周期（框架驱动，模块不重写这三个入口，只重写 on_* 扩展点）----
  bool init() {
    if (state_ != ServiceState::Created) return false;
    // 注册收敛（M0.9/ADR-0008）：订阅注册中心纪元广播——纪元变化 = 注册中心重启/目录丢失，
    // 全员立即重注册；框架内建，模块无感知。
    mgmt().subscribe(topics::RegistryAnnounce, [this](const Msg& m) {
      const std::string epoch = m.get("epoch");
      if (epoch.empty() || epoch == reg_epoch_) return;
      if (state_ != ServiceState::Running && state_ != ServiceState::DegradedState) return;
      if (register_self()) {
        logger_.info("service_reregistered", "registry epoch changed -> " + epoch);
        promote_after_register();
      }
    });
    if (!on_init()) { logger_.error("init_failed", "on_init returned false"); return false; }
    state_ = ServiceState::Initialized;
    return true;
  }

  // 启动：向服务注册中心注册（管理软总线 ServiceRegister），随后进入 Running。
  // 注册中心自身或注册不可达时按《架构说明》§8.4 降级启动（Degraded），不阻塞拉起，
  // 之后由 tick 的 rejoin 退避重试自动收敛（M0.9）。
  bool start() {
    if (state_ != ServiceState::Initialized) return false;
    if (register_self()) {
      state_ = ServiceState::Registered;
    } else {
      logger_.warn("register_unreachable", "service registry not reachable, start degraded",
                   {}, errc::SVC_NOT_REGISTERED);
      state_ = ServiceState::DegradedState;
    }
    if (!on_start()) { logger_.error("start_failed", "on_start returned false"); return false; }
    if (state_ == ServiceState::Registered) state_ = ServiceState::Running;
    logger_.info("service_started", std::string("state=") + to_string(state_));
    return true;
  }

  void stop() {
    if (state_ == ServiceState::Stopped) return;
    on_stop();
    state_ = ServiceState::Stopped;
    logger_.info("service_stopped", "bye");
  }

  // 心跳与周期任务：运行器按节拍调用（关键服务 5~100ms，普通 1s 级，见《架构说明》§7.2）
  void tick(std::uint64_t now) {
    if (state_ != ServiceState::Running && state_ != ServiceState::DegradedState) return;
    // 接收侧时钟钩子：在框架自身心跳与模块 on_tick 前推进。注册中心用它给同步
    // 总线回调标记服务端接收时刻，避免信任参与方 timestamp；其他模块缺省无动作。
    on_tick_begin(now);
    if (heartbeat_period_ms_ > 0 && now - last_beat_ms_ >= heartbeat_period_ms_) {
      last_beat_ms_ = now;
      Msg hb{"Heartbeat", {{"service_id", id_.service_id},
                           {"node_id", id_.node_id.empty() ? "local" : id_.node_id},
                           {"instance_id", id_.instance_id},
                           {"timestamp", std::to_string(now)},
                           {"health", to_string(health_)}}};
      mgmt().publish(topics::ServiceHeartbeat, hb);
    }
    // rejoin 退避重试（M0.9）：降级启动/注册中心离线期间，按周期重试直至收敛
    if (!registered_ && now - last_reg_try_ms_ >= config().get_u64("service.rejoin_ms", 3000)) {
      last_reg_try_ms_ = now;
      if (register_self()) {
        logger_.info("service_rejoined", "registry reachable, registered");
        promote_after_register();
      }
    }
    // 【2026-08-19】**周期重申注册**——上面那条只在"我还没注册上"时跑，
    // 而"注册中心把我忘了"这件事，本进程从自己这边看不出来：它照样心跳、照样 Running。
    // 现场实测（负责人拔网线）：链路断开期间租约到期，注册中心把记录判 down 并回收；
    // 网线插回后**节点画像与进程自报都自己恢复了**（那两条是周期上报），
    // 唯独服务注册没有——目录里从此没有它，链步派不下去，报 OS2-3001「服务链非法」。
    // 纪元广播那条收敛也不触发：注册中心没重启，纪元没变。
    // 所以再补一条：注册着也周期重申。幂等、失败不降级，覆盖一切"目录忘了我"的原因
    // （注册中心重启 / 租约过期 / GC / 网络分区），最迟一个周期就自己回去。
    if (registered_ && last_reassert_ms_ == 0) last_reassert_ms_ = now;  // 起点＝注册那一刻
    if (registered_ && now - last_reassert_ms_ >= config().get_u64("service.reassert_ms", 5000)) {
      last_reassert_ms_ = now;
      // **失败不降级**：register_self() 会把 registered_ 置成结果，而一次瞬时失败
      // 不该把一个正在正常心跳的服务打成未注册——那会让它转去走上面那条 rejoin，
      // 反而更慢。这里存下来再放回去。
      const bool was = registered_;
      if (!register_self() && was) registered_ = true;
    }
    on_tick(now);
  }

  // ---- 只读观测 ----
  const ServiceIdentity& identity() const { return id_; }
  ServiceState state() const { return state_; }
  Health health() const { return health_; }

 protected:
  // ---- 模块扩展点（模块框架类/实现类重写）----
  virtual bool on_init() { return true; }         // 装配内部状态、订阅主题
  virtual bool on_start() { return true; }        // 注册后的启动动作
  virtual void on_stop() {}
  virtual void on_tick_begin(std::uint64_t /*now*/) {}
  virtual void on_tick(std::uint64_t /*now*/) {}  // 周期任务（租约检查、快照发布等）

  // ---- 框架提供给模块的受控能力 ----
  IBus& mgmt() { return *ctx_.buses.mgmt; }
  IBus& biz() { return *ctx_.buses.biz; }
  const Config& config() const { return ctx_.config; }
  Logger& log() { return logger_; }

  void set_health(Health h, const std::string& reason = {}) {
    if (h == health_) return;
    health_ = h;
    emit_event("health_changed", h == Health::Ok ? "info" : "warn", to_string(h), reason);
    if (h == Health::Degraded) state_ = ServiceState::DegradedState;
    else if (h == Health::Ok && state_ == ServiceState::DegradedState) state_ = ServiceState::Running;
  }

  void set_heartbeat_period(std::uint64_t ms) { heartbeat_period_ms_ = ms; }

  // 统一证据出口：Event → 管理软总线；Metric → MetricIngest（《架构说明》§4.1 每模块必须输出证据）
  void emit_event(const std::string& type, const std::string& level,
                  const std::string& state, const std::string& reason,
                  const std::string& trace_id = {}) {
    Event e{id_.service_id, type, level, state, reason, now_ms(), trace_id};
    mgmt().publish(topics::AlarmEvent, to_msg(e));
  }
  void emit_metric(const std::string& name, double value, const std::string& labels_json = "{}") {
    Metric m{name, labels_json, value, now_ms(), "good"};
    mgmt().publish(topics::MetricIngest, to_msg(m));
  }

 private:
  bool register_self() {
    // endpoint 语义：服务经软总线可达，定位 = 节点/实例（跨节点注册时注册中心
    // 由此获得部署位置证据；《架构说明》§8.2 实装矩阵的运行时映像）。
    const std::string node = id_.node_id.empty() ? "local" : id_.node_id;
    Msg req{"ServiceRegisterRequest",
            {{"service_id", id_.service_id}, {"version", id_.version},
             {"domain", to_string(id_.domain)}, {"node_id", node},
             {"endpoint", "bus://" + node + "/" + id_.instance_id},
             {"instance_id", id_.instance_id}}};
    auto rep = mgmt().request(topics::ServiceRegister, req, 500);
    registered_ = rep && rep->get("accepted") == "true";
    if (registered_) reg_epoch_ = rep->get("epoch");  // 记住注册中心纪元（收敛判据）
    return registered_;
  }

  // 注册成功后的状态提升：仅当此前因未注册而降级、且健康本身无恙时回 Running
  void promote_after_register() {
    if (state_ == ServiceState::DegradedState && health_ == Health::Ok)
      state_ = ServiceState::Running;
  }

  ServiceIdentity id_;
  ServiceContext ctx_;
  Logger logger_;
  ServiceState state_{ServiceState::Created};
  Health health_{Health::Ok};
  std::uint64_t heartbeat_period_ms_{1000};
  std::uint64_t last_beat_ms_{0};
  bool registered_{false};
  std::string reg_epoch_;
  std::uint64_t last_reg_try_ms_{0};
  std::uint64_t last_reassert_ms_{0};   // 周期重申注册，见 tick()
};

}  // namespace os2
