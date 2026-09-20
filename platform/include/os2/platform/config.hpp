// =============================================================================
// os2/platform/config.hpp — 极简配置（key=value 文本 + 环境变量覆盖）
// 运行配置的权威生成者是模型与数据管理器（《架构说明》§8.6）；本类只是读取器。
// =============================================================================
#pragma once

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>

namespace os2 {

class Config {
 public:
  Config() = default;
  explicit Config(std::map<std::string, std::string> kv) : kv_(std::move(kv)) {}

  // 文件格式：每行 key=value，# 开头为注释
  static Config from_file(const std::string& path) {
    std::map<std::string, std::string> kv;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
      if (line.empty() || line[0] == '#') continue;
      auto eq = line.find('=');
      if (eq == std::string::npos) continue;
      kv[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return Config(std::move(kv));
  }

  // 读取顺序：环境变量 OS2_<KEY大写> > 配置项 > 缺省值
  std::string get(const std::string& key, const std::string& dflt = {}) const {
    std::string env_key = "OS2_";
    for (char c : key) env_key += (c == '.' || c == '-') ? '_' : std::toupper(c);
    // M8 受控 profile 会装入环境覆盖白名单；空白名单仅保留非 profile/存量调用方的
    // 兼容行为。受控模式下，禁止项即使存在于进程环境也不会改变运行配置。
    if ((env_allowlist_.empty() || env_allowlist_.count(key)) != 0)
      if (const char* v = std::getenv(env_key.c_str())) return v;
    auto it = kv_.find(key);
    return it == kv_.end() ? dflt : it->second;
  }
  std::uint64_t get_u64(const std::string& key, std::uint64_t dflt = 0) const {
    auto s = get(key);
    return s.empty() ? dflt : std::strtoull(s.c_str(), nullptr, 10);
  }
  void set(const std::string& key, const std::string& value) { kv_[key] = value; }
  void set_env_allowlist(std::set<std::string> keys) {
    env_allowlist_ = std::move(keys);
  }
  // 全量视图（前缀扫描类装配用，如 sched.wcet.*；环境变量覆盖仍以 get() 为准）
  const std::map<std::string, std::string>& all() const { return kv_; }

 private:
  std::map<std::string, std::string> kv_;
  std::set<std::string> env_allowlist_;
};

}  // namespace os2
