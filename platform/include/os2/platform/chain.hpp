// =============================================================================
// os2/platform/chain.hpp — 服务链模型（SC-XML 镜像）+ 极简解析器 + DAG 校验
//
// 权威源：contracts/sc-xml/service_chain.xsd（《服务链结构协议(SC-XML)》）。
// 解析器只覆盖 XSD 定义的骨架格式（属性式 Node/Edge），够 M0.5 原型联调；
// 完整 XML 处理随 M1 契约代码生成引入。DAG 校验逻辑属契约层，调度算法不在此。
// =============================================================================
#pragma once

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "os2/platform/contracts.hpp"

namespace os2 {

struct ChainNode {
  std::string id;
  std::string service;         // 如 device-supervisor.read
  Criticality criticality{Criticality::C};
};

struct ChainEdge { std::string from, to; };

struct ServiceChain {
  std::string id;
  std::uint64_t deadline_ms{0};
  std::vector<ChainNode> nodes;
  std::vector<ChainEdge> edges;

  // DAG 校验：节点非空、边引用存在、无环。返回错误信息；合法返回 nullopt。
  std::optional<std::string> validate() const {
    if (nodes.empty()) return "chain has no nodes";
    std::set<std::string> ids;
    for (auto& n : nodes) {
      if (!ids.insert(n.id).second) return "duplicate node id: " + n.id;
    }
    for (auto& e : edges) {
      if (!ids.count(e.from)) return "edge from unknown node: " + e.from;
      if (!ids.count(e.to)) return "edge to unknown node: " + e.to;
    }
    if (!topo_order()) return "chain has a cycle";
    return std::nullopt;
  }

  // 拓扑序（Kahn）。有环返回 nullopt。
  std::optional<std::vector<ChainNode>> topo_order() const {
    std::map<std::string, int> indeg;
    std::map<std::string, std::vector<std::string>> next;
    for (auto& n : nodes) indeg[n.id] = 0;
    for (auto& e : edges) { ++indeg[e.to]; next[e.from].push_back(e.to); }
    std::vector<std::string> q;
    for (auto& [id, d] : indeg) if (d == 0) q.push_back(id);
    std::vector<ChainNode> out;
    while (!q.empty()) {
      std::sort(q.begin(), q.end());  // 确定性
      auto id = q.front(); q.erase(q.begin());
      out.push_back(*std::find_if(nodes.begin(), nodes.end(),
                                  [&](const ChainNode& n) { return n.id == id; }));
      for (auto& t : next[id]) if (--indeg[t] == 0) q.push_back(t);
    }
    if (out.size() != nodes.size()) return std::nullopt;
    return out;
  }
};

namespace detail {
inline std::string attr(const std::string& tag, const std::string& name) {
  auto key = name + "=\"";
  auto p = tag.find(key);
  if (p == std::string::npos) return {};
  p += key.size();
  auto q = tag.find('"', p);
  return q == std::string::npos ? std::string{} : tag.substr(p, q - p);
}
}  // namespace detail

// 解析 SC-XML 骨架（属性式）。失败返回 nullopt。
inline std::optional<ServiceChain> parse_sc_xml(const std::string& xml) {
  auto root = xml.find("<ServiceChain");
  if (root == std::string::npos) return std::nullopt;
  auto root_end = xml.find('>', root);
  std::string root_tag = xml.substr(root, root_end - root);

  ServiceChain c;
  c.id = detail::attr(root_tag, "id");
  auto dl = detail::attr(root_tag, "deadline_ms");
  c.deadline_ms = dl.empty() ? 0 : std::strtoull(dl.c_str(), nullptr, 10);
  if (c.id.empty()) return std::nullopt;

  for (std::size_t p = xml.find('<', root_end); p != std::string::npos; p = xml.find('<', p + 1)) {
    auto e = xml.find('>', p);
    if (e == std::string::npos) break;
    std::string tag = xml.substr(p, e - p);
    if (tag.rfind("<Node", 0) == 0) {
      c.nodes.push_back(ChainNode{detail::attr(tag, "id"), detail::attr(tag, "service"),
                                  criticality_from(detail::attr(tag, "criticality"))});
    } else if (tag.rfind("<Edge", 0) == 0) {
      c.edges.push_back(ChainEdge{detail::attr(tag, "from"), detail::attr(tag, "to")});
    }
  }
  return c;
}

}  // namespace os2
