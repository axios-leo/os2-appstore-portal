# OS² C++ 编码标准（v1）

**适用：** `platform/`、`modules/`、`sim/` 全部 C++ 代码。人与 AI 代理同等强制。

## 1 语言与依赖

- C++17，禁编译器扩展；`-Wall -Wextra -Werror` 是构建默认，警告=错误。
- 运行时零第三方依赖（现状）；引入依赖须 ADR + third_party/ 锁版本。
- 异常：允许标准库抛出，但模块代码**不得用异常做业务控制流**；跨模块边界一律错误码
  （`errc::*`）+ Reply/Event。`optional` 表达"可能没有"。

## 2 命名与布局

- 文件 `snake_case.hpp/.cpp`；类型 `PascalCase`；函数/变量 `snake_case`；
  成员变量尾下划线 `foo_`；常量 `kCamelCase` 或 `UPPER`（错误码沿契约原文）。
- 命名空间：`os2::platform` 框架、`os2::<module>` 模块、`os2::<module>::impl` 实现。
- 头文件自包含 + `#pragma once`；include 顺序：本模块 → os2/platform → 标准库（现状按
  clang-format 分组即可）。列宽 100。
- 注释用中文，文件头注明：职责、权威规约出处、Owner、扩展点边界。

## 3 框架使用规矩（复述三条最常违反的）

- 通信只经 `IBus` + `topics::*` 常量；禁止手写主题字符串。
- 日志只经 `log()`，必带 trace_id（有则必传）、错误必带 `errc::*`。
- 模块状态封装在服务类内；禁止全局可变状态、禁止单例。

## 4 测试标准

- 框架/模块代码：每个公开行为与每个扩展点实现至少一个 `OS2_TEST`；
  失败路径（拒绝/超时/越权）必须有用例——桩宽松、测试从严。
- 单测隔离：每用例自建 `BusPair::make_inproc()`；不共享服务实例；不依赖执行顺序。
- 集成级：新功能若影响链路，必须让 `make e2e`（及 testbed 场景）体现其证据。

## 5 提交前自检清单

1. `make build`（零警告）2. `make test`（11+ 全绿）3. `make contracts-check`
4. 新增错误码/主题？→ 先契约后镜像 5. 日志/trace/证据齐全 6. 提交尾注
   Task-Id/Spec-Ref（AI 另加 Generated-by）。

## 变更履历

| 日期 | 变更 |
|---|---|
| 2026-07-03 | 首建。 |
