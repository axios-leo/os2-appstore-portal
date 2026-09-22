# `test_appstore_portal.cpp` 代码讲解

源码：`/home/haoran/os-module/modules/appstore-portal/tests/test_appstore_portal.cpp`

## 1. 文件的总体职责

这个文件验证 `StoreService` 最基础的业务闭环：

- 缺少摘要的制品会被拒绝。
- 合法制品能够发布并登记。
- 通过安全策略检查后可以激活。
- 已激活制品可以回滚。
- 没有策略服务时必须拒绝激活。

它测试的是应用商店公共骨架，不涉及真实制品文件、严格 SHA-256、数字签名或灰度推进。

## 2. 被测代码与调用关系

```text
test_appstore_portal.cpp
    ↓ 创建
StoreService
    ↓ 使用
DigestVerifier
    ↓ 经管理总线调用
handle_publish() / handle_activation()
```

测试采用 `InProcBus`，所有消息都在当前进程同步调用，不需要启动真实中间件。

## 3. 依赖与命名空间

```cpp
#include "store_service.hpp"
#include "os2/platform/testing.hpp"
```

- `store_service.hpp`：提供被测类 `StoreService`。
- `testing.hpp`：提供 `OS2_TEST`、`OS2_ASSERT` 和 `OS2_ASSERT_EQ`。

```cpp
using namespace os2;
using namespace os2::store;
```

这样可以直接写 `ServiceContext`、`StoreService`，不必每次写完整命名空间。

## 4. 测试框架的输入输出

### `OS2_TEST(name)`

输入是测试名称，输出是一个自动注册的测试函数。

### `OS2_ASSERT(condition)`

输入是布尔条件。条件为假时记录失败文件和行号，但不会立即终止整个测试进程。

### `OS2_ASSERT_EQ(a, b)`

输入两个表达式。二者不相等时记录实际值和期望值。

### `run_all()`

执行所有注册测试。全部通过返回 `0`，存在失败返回 `1`。

## 5. `publish_activate_rollback_with_policy`

```cpp
OS2_TEST(publish_activate_rollback_with_policy)
```

### 测试目标

验证有策略服务放行时，发布、激活和回滚能够形成完整闭环。

### 输入与环境

```cpp
ServiceContext ctx{BusPair::make_inproc(), Config{}};
```

- 输入总线：一对进程内总线。
- 输入配置：空配置。
- 输出：测试上下文 `ctx`。

策略桩：

```cpp
ctx.buses.mgmt->serve(topics::PolicyCheck,
    [](const Msg&) { return Msg{"PolicyDecision", {{"allow", "true"}}}; });
```

输入任意策略请求，固定输出 `allow=true`。

服务对象输入：

```text
service_id  = os2.core.appstore-portal
version     = 0.1.0
domain      = Hmi
node_id     = hmi-01
instance_id = 空，由框架生成
```

### 执行步骤与断言

1. `s.init() && s.start()`：期望服务初始化和启动成功。
2. 发布没有 `sha256` 的 `app-x@1.0`：期望 `accepted=false`。
3. 再发布带 `sha256=abc123` 的相同制品：期望 `accepted=true`。
4. 构造 `activate` 命令并请求 `ActivationCommand`。
5. 期望回复成功，查询状态为 `activated`。
6. 构造 `rollback` 命令。
7. 期望回复成功，查询状态为 `rolled-back`。

### 输入输出汇总

| 阶段 | 输入 | 期望输出 |
|---|---|---|
| 错误发布 | 无摘要制品 | `accepted=false` |
| 正常发布 | 带摘要制品 | `accepted=true` |
| 激活 | `command_type=activate` | 成功，状态 `activated` |
| 回滚 | `command_type=rollback` | 成功，状态 `rolled-back` |

### 覆盖的生产函数

- `StoreService::on_init()`
- `StoreService::handle_publish()`
- `DigestVerifier::verify()`
- `StoreService::handle_activation()`
- `StoreService::find()`

## 6. `activation_denied_without_policy`

```cpp
OS2_TEST(activation_denied_without_policy)
```

### 测试目标

验证安全策略服务不存在时，激活操作采用“默认拒绝”原则。

### 输入与环境

创建进程内总线和空配置，但故意不注册 `PolicyCheck` 应答方。

### 执行步骤

1. 创建并启动 `StoreService`。
2. 发布 `app-y@1`，摘要为 `z`。
3. 构造 `activate` 命令。
4. `handle_activation()` 请求 `PolicyCheck`。
5. 总线找不到应答方，返回 `nullopt`。
6. 应用商店返回权限拒绝。

### 输入输出

**输入：**

```text
target_id    = app-y
command_type = activate
operator_id  = someone
```

**期望输出：**

- `reply_from(*r).ok() == false`
- `reason_code == SEC_DENIED`

### 覆盖的生产逻辑

```cpp
if (!dec || dec->get("allow") != "true")
  return Reply::failure(... SEC_DENIED ...);
```

## 7. `main()`

```cpp
int main() { return os2::testing::run_all(); }
```

**输入：** 无。

**输出：** 进程退出码。

- `0`：全部测试通过。
- `1`：至少一个断言失败。

## 8. 测试覆盖与未覆盖内容

已覆盖：发布、默认摘要检查、查询、策略放行、策略缺失、激活、回滚。

未覆盖：真实文件、64 位摘要、签名、灰度、持久化。这些由另外两个测试文件覆盖。

## 9. 运行方式

```bash
cd /home/haoran/os-module
cmake --build build -j2
ctest --test-dir build -R '^test_appstore_portal$' --output-on-failure
```

## 10. 阅读时最应该记住的三点

1. 测试通过管理总线调用服务，而不是直接调用私有函数。
2. `PolicyCheck` 是测试桩，模拟安全模块的应答。
3. 这个文件验证公共流程，真实制品接收由 `test_artifact_receiver.cpp` 验证。

