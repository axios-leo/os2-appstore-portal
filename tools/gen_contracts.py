#!/usr/bin/env python3
"""契约代码生成器（M1，ADR-0012）——手写镜像退役。

输入（契约真相源，均在 contracts/）：
  VERSION                               → kContractVersion（OS2-API 冻结口径）
  data-dictionary/data_dictionary.yaml  → 枚举镜像（cpp_type 标注者）
  error-codes/error_codes.yaml          → errc:: 常量
  topics/topics.yaml                    → topics:: 主题清单
  idl/os2_common.idl                    → 四类消息结构体 + Msg 映射函数

输出：platform/include/os2/platform/contracts.hpp（AUTO-GENERATED，禁止手改）。
确定性：同一输入字节级同一输出（契约门禁靠"再生成+比对"判漂移）。
用法：gen_contracts.py [--check]   --check 只比对不写回，漂移时退出码 1。
"""
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    print("需要 pyyaml：pip install pyyaml")
    sys.exit(1)

REPO = pathlib.Path(__file__).resolve().parents[1]
ROOT = REPO / "contracts"
OUT = REPO / "platform/include/os2/platform/contracts.hpp"

# C++ 保留字/冲突名 → 成员名改写（kv 线上键保持 IDL 原名）
RENAME = {"operator": "operator_id"}
RENAME_NOTE = {"operator": "操作者（IDL 字段名 operator，C++ 保留字故加后缀）"}
TYPE_MAP = {"string": "std::string", "unsigned long long": "std::uint64_t",
            "double": "double", "long": "std::int64_t"}
DEFAULTS = {("Metric", "quality"): '{"good"}'}  # 其余数值型一律 {0}


def load_idl():
    """解析 os2_common.idl：结构体 → [(idl_type, idl_name, comment)]（保持声明序）。"""
    text = (ROOT / "idl/os2_common.idl").read_text(encoding="utf-8")
    structs = []
    for m in re.finditer(r"struct\s+(\w+)\s*\{(.*?)\};", text, re.S):
        fields = []
        for line in m.group(2).splitlines():
            fm = re.match(r"\s*(string|long|double|unsigned long long)\s+(\w+);\s*(?://\s*(.*))?", line)
            if fm:
                fields.append((fm.group(1), fm.group(2), (fm.group(3) or "").strip()))
        structs.append((m.group(1), fields))
    return structs


def cpp_field(struct, idl_type, name):
    cpp_t = TYPE_MAP[idl_type]
    member = RENAME.get(name, name)
    default = DEFAULTS.get((struct, name), "" if idl_type == "string" else "{0}")
    return cpp_t, member, default


def emit_enums(dd):
    out = []
    enums = [(k, v) for k, v in dd["enums"].items() if isinstance(v, dict) and v.get("cpp_type")]
    decls, helpers = [], []
    for _, e in enums:
        vals = ", ".join(v["cpp"] for v in e["values"])
        decls.append(f"enum class {e['cpp_type']} {{ {vals} }};  // {e.get('comment', '')}")
    for _, e in enums:
        t = e["cpp_type"]
        cases = "".join(f"case {t}::{v['cpp']}: return \"{v['token']}\"; "
                        for v in e["values"][:-1])
        helpers.append(f"inline const char* to_string({t} v) {{\n"
                       f"  switch (v) {{ {cases}default: return \"{e['values'][-1]['token']}\"; }}\n}}")
        if e.get("from_string"):
            lines = "".join(f"  if (s == \"{v['token']}\") return {t}::{v['cpp']};\n"
                            for v in e["values"][:-1])
            helpers.append(f"inline {t} {t.lower()}_from(const std::string& s) {{\n"
                           f"{lines}  return {t}::{e['values'][-1]['cpp']};\n}}")
    out.append("\n".join(decls))
    out.append("\n".join(helpers))
    return "\n\n".join(out)


def emit_errc(ec):
    rows = []
    for code in sorted(ec["errors"]):
        e = ec["errors"][code]
        rows.append((e["symbol"], code, e["domain"], e["message"]))
    w_sym = max(len(r[0]) for r in rows)
    w_dom = max(len(r[2]) for r in rows)
    body = "\n".join(
        f"inline constexpr const char* {sym:<{w_sym}} = \"{code}\"; // {dom:<{w_dom}} {msg}"
        for sym, code, dom, msg in rows)
    return f"namespace errc {{\n{body}\n}}  // namespace errc"


def emit_topics(tp):
    rows = tp["topics"]
    w_name = max(len(r["name"]) for r in rows)
    w_topic = max(len(r["topic"]) for r in rows) + 2
    out, last_group = [], None
    for r in rows:
        if r["group"] != last_group:
            out.append(f"// {r['group']}")
            last_group = r["group"]
        kind = {"reqrep": "req/rep", "pub": "pub", "prefix": "prefix"}[r["kind"]]
        note = f"（{r['note']}）" if r.get("note") else ""
        quoted = f"\"{r['topic']}\";"
        out.append(f"inline constexpr const char* {r['name']:<{w_name}} = {quoted:<{w_topic + 2}} // {kind}{note}")
    body = "\n".join(out)
    return f"namespace topics {{\n{body}\n}}  // namespace topics"


def emit_structs(structs):
    out = []
    for name, fields in structs:
        lines = []
        w = max(len(" ".join(cpp_field(name, t, n)[0:1])) for t, n, _ in fields)
        for t, n, comment in fields:
            cpp_t, member, default = cpp_field(name, t, n)
            note = RENAME_NOTE.get(n, comment)
            c = f"  // {note}" if note else ""
            lines.append(f"  {cpp_t:<{w}} {member}{default};{c}")
        body = "\n".join(lines)
        extra = ""
        if name == "Reply":
            extra = """
  bool ok() const { return result == "success"; }
  static Reply success(const Command& c, std::string state = {}) {
    return Reply{c.command_id, "success", errc::OK, {}, std::move(state), 0, now_ms(), c.trace_id};
  }
  static Reply failure(const Command& c, std::string reason, std::string state = {}) {
    return Reply{c.command_id, "failed", std::move(reason), {}, std::move(state), 0, now_ms(), c.trace_id};
  }"""
        out.append(f"struct {name} {{\n{body}{extra}\n}};")
    return "\n\n".join(out)


def emit_mappers(structs):
    out = []
    for name, fields in structs:
        puts, gets = [], []
        for t, n, _ in fields:
            member = RENAME.get(n, n)
            if t == "string":
                puts.append(f'{{"{n}", x.{member}}}')
                gets.append(f'm.get("{n}")')
            elif t == "double":
                puts.append(f'{{"{n}", std::to_string(x.{member})}}')
                gets.append(f'std::strtod(m.get("{n}", "0").c_str(), nullptr)')
            else:  # 整型
                puts.append(f'{{"{n}", std::to_string(x.{member})}}')
                gets.append(f'm.get_u64("{n}")')
        put_body = ", ".join(puts)
        get_body = ", ".join(gets)
        out.append(f"inline Msg to_msg(const {name}& x) {{\n"
                   f"  return Msg{{\"{name}\", {{{put_body}}}}};\n}}")
        out.append(f"inline {name} {name.lower()}_from(const Msg& m) {{\n"
                   f"  return {name}{{{get_body}}};\n}}")
    return "\n".join(out)


def emit_msgspec(dd):
    """从 data_dictionary messages 段生成 os2::msgspec 校验规则表（RFC-0005，字典→gen 表）。

    仅生成**数据表**（枚举 token 集 + 逐主题/方向字段规则 + TopicSpec 索引）；判定逻辑
    在手写 platform/msg_validator.hpp 的 MsgValidator（数据/引擎分离，生成物确定性）。
    """
    msgs = dd.get("messages", {})
    enums = dd.get("enums", {})
    KIND = {"string": "Kind::String", "number": "Kind::Number", "enum": "Kind::Enum"}
    DIRS = ("req", "rep", "pub")

    # 被引用枚举（type: enum 字段）→ 合法 token 集（排序保证生成确定性）
    referenced = []
    for _, secs in msgs.items():
        for d in DIRS:
            for f in secs.get(d, []):
                if f.get("type") == "enum" and f["enum"] not in referenced:
                    referenced.append(f["enum"])
    referenced.sort()
    tok_lines = ["inline constexpr const char* const kTok_%s[] = {%s, nullptr};"
                 % (en, ", ".join('"%s"' % v["token"] for v in enums[en]["values"]))
                 for en in referenced]

    # 逐主题/方向字段数组 + TopicSpec 索引（文件序 × req/rep/pub 固定序）
    field_arrays, specs = [], []
    for topic, secs in msgs.items():
        for d in DIRS:
            fields = secs.get(d, [])
            if not fields:
                continue
            arr = "kFields_%s_%s" % (topic, d)
            rows = ['  {"%s", %s, %s, %s, %s},' % (
                f["key"], KIND.get(f.get("type", "string"), "Kind::String"),
                "true" if f.get("opt") else "false",
                "true" if f.get("pattern") else "false",
                ("kTok_%s" % f["enum"]) if f.get("type") == "enum" else "nullptr")
                for f in fields]
            field_arrays.append("inline constexpr Field %s[] = {\n%s\n};" % (arr, "\n".join(rows)))
            specs.append('  {"%s", "%s", %s, %d},' % (topic, d, arr, len(fields)))

    head = """namespace msgspec {
// 消息边界校验规则（生成自 data_dictionary.yaml messages 段，RFC-0005 v1.5.0）。
// 平台 MsgValidator（os2/platform/msg_validator.hpp）据此对进站 Msg 做类型/尺寸/拒收
// 校验；校验 opt-in 逐主题（bus.validate）、缺省关。此处仅数据表，判定逻辑在 MsgValidator。
enum class Kind : char { String = 's', Number = 'n', Enum = 'e' };
struct Field {
  const char* key;                 // 键名（线上 kv 键）
  Kind kind;                       // 期望类型
  bool opt;                        // 可选键（缺失不违规）
  bool pattern;                    // 动态键模板（前缀匹配，存在性不强制）
  const char* const* enum_tokens;  // 合法 token 集（Enum 专用，nullptr 结尾），否则 nullptr
};
struct TopicSpec {
  const char* topic;   // 主题名（=topics.yaml 名 / MsgValidator::for_topic 键）
  const char* dir;     // 方向：req/rep/pub
  const Field* fields;
  std::size_t count;
};"""
    tail = ("inline constexpr TopicSpec kMsgSpecs[] = {\n%s\n};\n"
            "inline constexpr std::size_t kMsgSpecCount = sizeof(kMsgSpecs) / sizeof(kMsgSpecs[0]);\n"
            "}  // namespace msgspec" % "\n".join(specs))
    blocks = [head]
    if tok_lines:
        blocks.append("\n".join(tok_lines))
    if field_arrays:
        blocks.append("\n\n".join(field_arrays))
    blocks.append(tail)
    return "\n\n".join(blocks)


def generate():
    ver = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    dd = yaml.safe_load((ROOT / "data-dictionary/data_dictionary.yaml").read_text(encoding="utf-8"))
    ec = yaml.safe_load((ROOT / "error-codes/error_codes.yaml").read_text(encoding="utf-8"))
    tp = yaml.safe_load((ROOT / "topics/topics.yaml").read_text(encoding="utf-8"))
    structs = load_idl()

    return f"""// =============================================================================
// os2/platform/contracts.hpp — 契约类型的 C++ 镜像
//
// ⚠ AUTO-GENERATED by tools/gen_contracts.py — 禁止手改（改契约源后 make contracts-gen）
// 真相源：contracts/VERSION（契约版本，OS2-API 冻结口径）
//         contracts/data-dictionary/data_dictionary.yaml（枚举/字段）
//         contracts/error-codes/error_codes.yaml（错误码全集）
//         contracts/topics/topics.yaml（主题清单，《架构说明》§8.7 机读形态）
//         contracts/idl/os2_common.idl（Command/Reply/Event/Metric，《架构说明》§6.2）
// 门禁：make contracts-check = 再生成 + 字节比对，漂移即失败（E-2 §5 门禁 D）。
// 变更流程：契约源改动走 RFC → L0 仲裁 → 重新生成提交（ADR-0012）；
//           v1.0 冻结后按版本流程（docs/reviews/2026-07-10-contract-freeze-review.md §4）。
// =============================================================================
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <optional>
#include <random>
#include <string>

namespace os2 {{

// ---------------------------------------------------------------------------
// 契约版本（生成自 contracts/VERSION）——OS2-API 冻结基线，页面/接口回显用真值
// ---------------------------------------------------------------------------
inline constexpr const char* kContractVersion = "{ver}";

// ---------------------------------------------------------------------------
// 数据字典枚举（生成自 data_dictionary.yaml enums.*.cpp_type）
// ---------------------------------------------------------------------------
{emit_enums(dd)}

// ---------------------------------------------------------------------------
// 错误码（生成自 error_codes.yaml；新增先改 yaml 再 make contracts-gen）
// ---------------------------------------------------------------------------
{emit_errc(ec)}

// ---------------------------------------------------------------------------
// 主题清单（生成自 topics.yaml）。管理面走管理软总线，业务面走业务软总线。
// 模块间只允许通过这些主题交互 —— 这是运行时的边界铁律。
// ---------------------------------------------------------------------------
{emit_topics(tp)}

// ---------------------------------------------------------------------------
// 通用工具：时间与 ID（trace_id/command_id 生成）
// ---------------------------------------------------------------------------
inline std::uint64_t now_ms() {{
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count());
}}

inline std::string gen_id(const std::string& prefix) {{
  static thread_local std::mt19937_64 rng{{std::random_device{{}}()}};
  char buf[17];
  std::snprintf(buf, sizeof(buf), "%016llx",
                static_cast<unsigned long long>(rng()));
  return prefix + "-" + buf;
}}

// ---------------------------------------------------------------------------
// 标准消息四元组（生成自 os2_common.idl，《架构说明》§6.2）
// 传输序列化在 PAL 适配器完成（wire v1 / DDS），字段即结构体成员。
// ---------------------------------------------------------------------------
{emit_structs(structs)}

// ---------------------------------------------------------------------------
// 总线报文：统一用 type + kv 承载（typed struct ↔ Msg 在本契约层完成映射，
// 模块代码不手拼 kv 键名 —— 这保证换传输/序列化时模块代码零改动）。
// ---------------------------------------------------------------------------
struct Msg {{
  std::string type;                             // 消息类型名，如 "Command"
  std::map<std::string, std::string> kv;        // 扁平字段
  std::string get(const std::string& k, const std::string& dflt = {{}}) const {{
    auto it = kv.find(k); return it == kv.end() ? dflt : it->second;
  }}
  std::uint64_t get_u64(const std::string& k, std::uint64_t dflt = 0) const {{
    auto it = kv.find(k); return it == kv.end() ? dflt : std::strtoull(it->second.c_str(), nullptr, 10);
  }}
  // 严格访问器（RFC-0005 支柱三）：缺失/非全量数值 → nullopt（区别于 get_u64 静默 0）；
  // 边界校验与"拒静默 0"读取路径用此，既有宽松 get_u64 保留不动（存量零改动）。
  std::optional<std::uint64_t> get_u64_checked(const std::string& k) const {{
    auto it = kv.find(k);
    if (it == kv.end() || it->second.empty()) return std::nullopt;
    char* end = nullptr;
    unsigned long long v = std::strtoull(it->second.c_str(), &end, 10);
    if (end == it->second.c_str() || *end != '\\0') return std::nullopt;
    return static_cast<std::uint64_t>(v);
  }}
  std::optional<double> get_num_checked(const std::string& k) const {{
    auto it = kv.find(k);
    if (it == kv.end() || it->second.empty()) return std::nullopt;
    char* end = nullptr;
    double v = std::strtod(it->second.c_str(), &end);
    if (end == it->second.c_str() || *end != '\\0') return std::nullopt;
    return v;
  }}
}};

{emit_mappers(structs)}

// ---------------------------------------------------------------------------
// 消息边界校验规则表（生成自 data_dictionary.yaml messages 段，RFC-0005 v1.5.0）
// 判定逻辑在 platform/msg_validator.hpp（数据/引擎分离）；opt-in 逐主题、缺省关。
// ---------------------------------------------------------------------------
{emit_msgspec(dd)}

}}  // namespace os2
"""


def main():
    text = generate()
    if "--check" in sys.argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print("ERR  contracts.hpp 与契约源漂移：请运行 make contracts-gen 并提交")
            return 1
        print("OK   contracts.hpp 与契约源一致（生成比对）")
        return 0
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"已生成 {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
