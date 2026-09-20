// =============================================================================
// os2/platform/msg_validator.hpp — 消息边界校验器（RFC-0005，契约 v1.5.0）
//
// 量产差距重审 F-11：数据面 Msg = map<string,string> 扁平字符串（contracts.hpp），
// get_u64 解析失败静默返回 0，且无尺寸约束——错值以 0 冒充成功、畸形/超大报文无拒收。
// 本原语把 data_dictionary messages 段已声明的 type/opt/pattern（生成为 os2::msgspec
// 规则表）转成运行时可执行的三支柱校验：
//   ① 运行时类型化：number 键须可解析为数值（拒静默 0）、enum 键值须在合法 token 集；
//   ② 尺寸约束：键数/单值长度/整报文尺寸上界（缺省 0=不限，存量宽松不破）；
//   ③ 失败拒收：任一违规 → 返回契约错误码（MSG_TYPE_REJECTED/MSG_SIZE_EXCEEDED），
//      调用方据此拒收 + 记证据事件，不进业务处理。
//
// 数据/引擎分离：规则**数据表**由 gen_contracts.py 生成（os2::msgspec）；本文件是手写
// **判定引擎**，生成物确定性不受判定逻辑影响。
//
// opt-in 逐主题（缺省关）：由调用方按 config bus.validate 决定是否启用（validate_enabled）；
// 未启用主题不构造校验器 = 行为零变化（同 F-08/x509 缺省关口径）。嵌套载荷（args_json/
// payload 子文档）本阶段不做（RFC-0005 §2.4 负责人搁置）——本器只校验扁平边界。
// =============================================================================
#pragma once

#include <cstddef>
#include <cstdlib>
#include <optional>
#include <string>

#include "os2/platform/config.hpp"
#include "os2/platform/contracts.hpp"

namespace os2::msgv {

// 尺寸约束（支柱二）。缺省 0 = 不限（存量宽松不破）。配置键 bus.max_*。
struct SizeLimits {
  std::size_t max_fields{0};     // bus.max_fields：kv 条数上界
  std::size_t max_value_len{0};  // bus.max_value_len：单值字节上界（防超大字段）
  std::size_t max_msg_bytes{0};  // bus.max_msg_bytes：整报文序列化尺寸上界

  static SizeLimits from_config(const Config& c) {
    SizeLimits s;
    s.max_fields = static_cast<std::size_t>(c.get_u64("bus.max_fields", 0));
    s.max_value_len = static_cast<std::size_t>(c.get_u64("bus.max_value_len", 0));
    s.max_msg_bytes = static_cast<std::size_t>(c.get_u64("bus.max_msg_bytes", 0));
    return s;
  }
  bool any() const { return max_fields || max_value_len || max_msg_bytes; }
};

// 违规裁决：code = 契约错误码常量（errc::MSG_TYPE_REJECTED / MSG_SIZE_EXCEEDED，静态存储）。
struct Violation {
  const char* code;    // errc:: 常量
  std::string detail;  // 人读定位（键名/期望），入日志与证据事件
};

// opt-in 判定：topic 是否在 config bus.validate（逗号分隔主题清单；"*" = 全部）中。
// 缺省空 = 关（返回 false）——未启用主题零行为变化。
inline bool validate_enabled(const Config& cfg, const std::string& topic) {
  const std::string csv = cfg.get("bus.validate");
  if (csv.empty()) return false;
  std::size_t i = 0;
  while (i <= csv.size()) {
    std::size_t j = csv.find(',', i);
    if (j == std::string::npos) j = csv.size();
    std::size_t a = i, b = j;
    while (a < b && (csv[a] == ' ' || csv[a] == '\t')) ++a;
    while (b > a && (csv[b - 1] == ' ' || csv[b - 1] == '\t')) --b;
    if (b > a) {
      const std::string tok = csv.substr(a, b - a);
      if (tok == "*" || tok == topic) return true;
    }
    if (j == csv.size()) break;
    i = j + 1;
  }
  return false;
}

// 消息边界校验器：绑定某主题/方向的规则表 + 尺寸门。无匹配 spec → 仅尺寸门。
class MsgValidator {
 public:
  // topic/dir 与 os2::msgspec 表一致（如 "ProgramControlCommand","req"）。
  static MsgValidator for_topic(const std::string& topic, const std::string& dir,
                                SizeLimits lim) {
    const msgspec::TopicSpec* found = nullptr;
    for (std::size_t k = 0; k < msgspec::kMsgSpecCount; ++k) {
      const msgspec::TopicSpec& s = msgspec::kMsgSpecs[k];
      if (topic == s.topic && dir == s.dir) {
        found = &s;
        break;
      }
    }
    return MsgValidator(found, lim);
  }

  // nullopt = 通过；否则给出首个违规（尺寸门先于类型门）。
  std::optional<Violation> check(const Msg& m) const {
    // ② 尺寸门（缺省 0 不限）
    if (lim_.max_fields && m.kv.size() > lim_.max_fields)
      return Violation{errc::MSG_SIZE_EXCEEDED,
                       "fields=" + std::to_string(m.kv.size()) + " > " +
                           std::to_string(lim_.max_fields)};
    std::size_t total = m.type.size();
    for (const auto& kv : m.kv) {
      if (lim_.max_value_len && kv.second.size() > lim_.max_value_len)
        return Violation{errc::MSG_SIZE_EXCEEDED,
                         "value_len key=" + kv.first + " len=" +
                             std::to_string(kv.second.size())};
      total += kv.first.size() + kv.second.size();
    }
    if (lim_.max_msg_bytes && total > lim_.max_msg_bytes)
      return Violation{errc::MSG_SIZE_EXCEEDED,
                       "msg_bytes=" + std::to_string(total) + " > " +
                           std::to_string(lim_.max_msg_bytes)};

    // ①/③ 类型门 + 失败拒收（仅当有规则表）
    if (spec_) {
      for (std::size_t i = 0; i < spec_->count; ++i) {
        const msgspec::Field& f = spec_->fields[i];
        if (f.pattern) {  // 动态键模板：前缀匹配已存在的实键做类型校验（存在性不强制）
          if (auto bad = check_pattern(f, m)) return bad;
          continue;
        }
        auto it = m.kv.find(f.key);
        if (it == m.kv.end()) {
          if (f.opt) continue;  // 可选键缺失不违规
          return Violation{errc::MSG_TYPE_REJECTED,
                           std::string("missing required key: ") + f.key};
        }
        if (auto bad = check_value(f, f.key, it->second)) return bad;
      }
    }
    return std::nullopt;
  }

  bool has_spec() const { return spec_ != nullptr; }

 private:
  MsgValidator(const msgspec::TopicSpec* spec, SizeLimits lim) : spec_(spec), lim_(lim) {}

  static std::optional<Violation> check_value(const msgspec::Field& f, const std::string& key,
                                              const std::string& val) {
    if (f.kind == msgspec::Kind::Number) {
      if (!is_numeric(val))
        return Violation{errc::MSG_TYPE_REJECTED, "non-numeric: " + key + "=\"" + val + "\""};
    } else if (f.kind == msgspec::Kind::Enum) {
      if (!in_tokens(f.enum_tokens, val))
        return Violation{errc::MSG_TYPE_REJECTED, "bad enum: " + key + "=\"" + val + "\""};
    }
    return std::nullopt;  // String：存在即合规（长度约束已在尺寸门）
  }

  // 动态键模板：对所有以 "<prefix>" 开头的实键做类型校验（prefix = key 中 '<' 前子串）。
  static std::optional<Violation> check_pattern(const msgspec::Field& f, const Msg& m) {
    const std::string key(f.key);
    const std::size_t lt = key.find('<');
    const std::string prefix = lt == std::string::npos ? key : key.substr(0, lt);
    if (prefix.empty()) return std::nullopt;
    for (const auto& kv : m.kv) {
      if (kv.first.size() >= prefix.size() &&
          kv.first.compare(0, prefix.size(), prefix) == 0) {
        if (auto bad = check_value(f, kv.first, kv.second)) return bad;
      }
    }
    return std::nullopt;
  }

  // 数值判定：非空且被 strtod 全量消费（拒 ""/"abc"/"12x" 等 get_u64 静默 0 的病灶）。
  static bool is_numeric(const std::string& s) {
    if (s.empty()) return false;
    char* end = nullptr;
    std::strtod(s.c_str(), &end);
    return end != s.c_str() && *end == '\0';
  }

  static bool in_tokens(const char* const* toks, const std::string& val) {
    if (!toks) return true;
    for (const char* const* p = toks; *p != nullptr; ++p)
      if (val == *p) return true;
    return false;
  }

  const msgspec::TopicSpec* spec_;
  SizeLimits lim_;
};

}  // namespace os2::msgv
