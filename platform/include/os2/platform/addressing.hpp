// =============================================================================
// os2/platform/addressing.hpp — 实例寻址接收侧校验（R2-⑤/F-04）
// 量产差距重审在案问题：assigned_node 是解释字段非执行约束——调度器落位某实例，
// 但 os2.biz.svc.* 主题谁订谁答，错实例执行了也无人发现。本原语把"落位"变成
// 可执行约束的两半：
//   接收侧：请求带 node（调度落位）且 ≠ 本实例 → 拒绝且不执行业务副作用；
//   自证侧：应答一律盖 served_by=本实例 → 发送侧（调度器）核对回执来源。
// 不带 node 的请求视为不定向调用（兼容存量）。一期 SIL 界内为协议+框架原语；
// 每实例独立进程/容器编排=1.5期（负责人 §6-5 拆分）。
// =============================================================================
#pragma once

#include <utility>

#include "os2/platform/bus.hpp"

namespace os2::addressing {

inline constexpr const char* kNodeKey = "node";          // 请求：调度落位实例
inline constexpr const char* kServedByKey = "served_by"; // 应答：实际执行实例自证

// 包装业务应答方：错发拒绝 + 执行方身份自证。用法：
//   bus->serve(topic, addressing::addressed(self_node, handler));
inline ReqHandler addressed(std::string self_node, ReqHandler handler) {
  return [self = std::move(self_node), h = std::move(handler)](const Msg& m) -> Msg {
    const std::string want = m.get(kNodeKey);
    if (!want.empty() && want != self) {  // 定向请求发错实例：拒收，业务逻辑不执行
      return Msg{"MisroutedReply",
                 {{"result", "failed"},
                  {"reason", "misrouted: addressed=" + want + " self=" + self},
                  {kServedByKey, self},
                  {"trace_id", m.get("trace_id")}}};
    }
    Msg rep = h(m);
    rep.kv[kServedByKey] = self;
    return rep;
  };
}

}  // namespace os2::addressing
