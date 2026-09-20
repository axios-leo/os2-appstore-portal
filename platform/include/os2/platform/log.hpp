// =============================================================================
// os2/platform/log.hpp — 结构化日志（《技术规范》§12.3）
//
// 必备字段：timestamp/level/component/instanceId/traceId/domain/nodeId/
//           event/errorCode/message。输出 JSON Lines，便于日志切片与证据导出。
// =============================================================================
#pragma once

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "os2/platform/contracts.hpp"

namespace os2 {

struct LogRecord {
  std::uint64_t timestamp{0};
  std::string level;       // DEBUG/INFO/WARN/ERROR
  std::string component;   // 模块名，如 device-supervisor
  std::string instance_id;
  std::string trace_id;
  std::string domain;
  std::string node_id;
  std::string event;       // 事件短名，如 heartbeat_timeout
  std::string error_code;  // 契约错误码，正常时为空
  std::string message;
};

inline std::string json_escape(const std::string& s) {
  std::string out; out.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\t': out += "\\t"; break;
      default: out += c;
    }
  }
  return out;
}

inline std::string to_json(const LogRecord& r) {
  std::ostringstream o;
  o << "{\"timestamp\":" << r.timestamp
    << ",\"level\":\"" << r.level << "\""
    << ",\"component\":\"" << json_escape(r.component) << "\""
    << ",\"instanceId\":\"" << json_escape(r.instance_id) << "\""
    << ",\"traceId\":\"" << json_escape(r.trace_id) << "\""
    << ",\"domain\":\"" << json_escape(r.domain) << "\""
    << ",\"nodeId\":\"" << json_escape(r.node_id) << "\""
    << ",\"event\":\"" << json_escape(r.event) << "\""
    << ",\"errorCode\":\"" << json_escape(r.error_code) << "\""
    << ",\"message\":\"" << json_escape(r.message) << "\"}";
  return o.str();
}

// Logger：默认写 stderr；可挂 sink（如 ops-mgr 日志切片、测试断言）。
class Logger {
 public:
  using Sink = std::function<void(const LogRecord&)>;

  Logger() = default;
  Logger(std::string component, std::string instance_id,
         std::string domain, std::string node_id)
      : component_(std::move(component)), instance_id_(std::move(instance_id)),
        domain_(std::move(domain)), node_id_(std::move(node_id)) {}

  void add_sink(Sink s) { sinks_.push_back(std::move(s)); }
  void set_stderr(bool on) { stderr_ = on; }

  void log(const std::string& level, const std::string& event,
           const std::string& message, const std::string& trace_id = {},
           const std::string& error_code = {}) const {
    LogRecord r{now_ms(), level, component_, instance_id_, trace_id,
                domain_, node_id_, event, error_code, message};
    if (stderr_) std::cerr << to_json(r) << "\n";
    for (auto& s : sinks_) s(r);
  }
  void info(const std::string& ev, const std::string& msg, const std::string& tid = {}) const {
    log("INFO", ev, msg, tid);
  }
  void warn(const std::string& ev, const std::string& msg, const std::string& tid = {},
            const std::string& ec = {}) const { log("WARN", ev, msg, tid, ec); }
  void error(const std::string& ev, const std::string& msg, const std::string& tid = {},
             const std::string& ec = {}) const { log("ERROR", ev, msg, tid, ec); }

 private:
  std::string component_, instance_id_, domain_, node_id_;
  std::vector<Sink> sinks_;
  bool stderr_{true};
};

}  // namespace os2
