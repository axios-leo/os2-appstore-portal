// =============================================================================
// os2/platform/bus.hpp — 双软总线抽象 IBus 与进程内参考实现 InProcBus
//
// 架构依据：《架构说明》§5.2 双软总线隔离（业务软总线/管理软总线）+ PAL 统一原语
//           （Pub/Sub、Request/Reply=Command/Reply）。
//
// 边界（重要）：
//   * IBus 是全系统通信的唯一接缝。模块代码只依赖 IBus，不依赖任何具体传输。
//   * InProcBus 是"单机单进程"参考实现，用于单测与 single-node 集成仿真，
//     同步派发、确定性、零依赖 —— 它**不是**生产传输。
//   * DDS/TSN/RDMA/共享内存等真实适配由 comm-middleware-pal 模块实现
//     （实现 IBus 或其 ITransportAdapter，见该模块 api.hpp）—— 任务卡边界。
// =============================================================================
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "os2/platform/contracts.hpp"

namespace os2 {

enum class BusPlane { Management, Business };  // 双总线：管理面 / 业务面

inline const char* to_string(BusPlane p) {
  return p == BusPlane::Management ? "mgmt" : "biz";
}

// 订阅回调与应答回调
using SubHandler = std::function<void(const Msg&)>;
using ReqHandler = std::function<Msg(const Msg&)>;

// -----------------------------------------------------------------------------
// IBus — 统一通信原语（模块唯一可依赖的通信接口）
// -----------------------------------------------------------------------------
class IBus {
 public:
  virtual ~IBus() = default;

  // Pub/Sub：发布到主题；订阅主题（同一主题可多订阅者）
  virtual void publish(const std::string& topic, const Msg& msg) = 0;
  virtual void subscribe(const std::string& topic, SubHandler handler) = 0;

  // Request/Reply：单应答方语义（Command/Reply 闭环）
  //   serve()   注册主题的应答方（重复注册视为替换）
  //   request() 同步请求；无应答方/超时返回 nullopt
  virtual void serve(const std::string& topic, ReqHandler handler) = 0;
  virtual std::optional<Msg> request(const std::string& topic, const Msg& msg,
                                     std::uint64_t timeout_ms = 1000) = 0;

  // 协作式收发泵：网络化实现（PAL 适配器）在此排空入站报文并派发订阅回调。
  // 运行器（os2_node/testbed 主循环）按节拍调用；进程内实现为空操作。
  // 单线程执行模型（docs/FRAMEWORK.md §3）由此保持 —— 总线不自带线程。
  virtual void poll() {}

  // 阻塞等待期间的**空转钩子**：request() 是协作式等待（泵驱动、无线程），
  // 运行器把"本来每拍要做的事"塞进来，等待期间照常做。
  //
  // 为什么要它（2026-08-18 实测）：链步派发时执行代理在业务面 request 等服务返回，
  // 服务真业务一跑就是几秒到几十秒——这期间**整个节点主循环停住**，资源上报停、
  // 心跳停，这台机在别人眼里等于失联（演示节拍 10s 时心跳 age 涨到 10.3s）。
  // 这是量产问题，不只是演示不好看：真业务本来就要跑那么久。
  //
  // ⚠ 钩子里**只许"发"，不许再 request**：request 会往 subs_ 里插临时回执主题，
  // 而此刻外层可能正在派发（serve 回调里套着这次等待），嵌套改容器＝未定义行为，
  // 症状是**回执悄悄丢掉、对端等到超时**（第一版就是这么坏的）。
  virtual void set_idle_hook(std::function<void()>) {}
};

// -----------------------------------------------------------------------------
// InProcBus — 进程内同步参考实现（确定性、可测；非生产传输）
// -----------------------------------------------------------------------------
class InProcBus final : public IBus {
 public:
  explicit InProcBus(BusPlane plane) : plane_(plane) {}
  BusPlane plane() const { return plane_; }

  void publish(const std::string& topic, const Msg& msg) override {
    ++published_;
    auto it = subs_.find(topic);
    if (it == subs_.end()) return;
    for (auto& h : it->second) h(msg);
  }

  void subscribe(const std::string& topic, SubHandler handler) override {
    subs_[topic].push_back(std::move(handler));
  }

  void serve(const std::string& topic, ReqHandler handler) override {
    responders_[topic] = std::move(handler);
  }

  std::optional<Msg> request(const std::string& topic, const Msg& msg,
                             std::uint64_t /*timeout_ms*/) override {
    ++requested_;
    auto it = responders_.find(topic);
    if (it == responders_.end()) return std::nullopt;  // 无应答方 ≈ 超时
    return it->second(msg);
  }

  // 观测口径（《架构说明》§5.2 链路观测是总线内建能力）
  std::uint64_t published_count() const { return published_; }
  std::uint64_t requested_count() const { return requested_; }

 private:
  BusPlane plane_;
  std::map<std::string, std::vector<SubHandler>> subs_;
  std::map<std::string, ReqHandler> responders_;
  std::uint64_t published_{0};
  std::uint64_t requested_{0};
};

// 双总线组：一次性把两条总线交给服务上下文
struct BusPair {
  std::shared_ptr<IBus> mgmt;  // 管理软总线：注册/心跳/告警/日志/回执
  std::shared_ptr<IBus> biz;   // 业务软总线：采集/计算/控制/HMI/AI 数据

  static BusPair make_inproc() {
    return BusPair{std::make_shared<InProcBus>(BusPlane::Management),
                   std::make_shared<InProcBus>(BusPlane::Business)};
  }
};

}  // namespace os2
