# `grayscale_store.hpp` 代码讲解

源码：`modules/appstore-portal/src/impl/grayscale_store.hpp`

## 1. 文件的总体职责

这个文件给 `StoreService` 增加四类能力：

1. 更严格的制品 id、版本和 SHA-256 格式检查。
2. 按配置启用 X.509 制品签名验证。
3. 激活后按 10%、50%、100% 灰度推进，并在严重告警时自动回滚。
4. 持久化和恢复正在进行的 staged 灰度批次，使重启后能够继续推进。

它还在周期任务中先调用部署超时检查，再调用 `persist_tick()`，保证 D2 部署任务、
制品状态和灰度扩展状态能够落盘。

## 2. 继承和组合关系

```text
StoreService
    ↓
GrayscaleStore
    ├─ make_verifier()
    │    ├─ Sha256FormatVerifier
    │    └─ 可选 SignatureArtifactVerifier
    ├─ on_activated()
    ├─ on_tick()
    └─ AlarmEvent 健康门控
```

## 3. 两种灰度模式

### immediate

默认模式。制品激活时立即记录：

```text
10% → 50% → 100%
```

它适合台架和演示，三批不等待真实观察窗。

### staged

配置：

```text
store.rollout_mode=staged
```

激活时只推进到 10%，后续由 `tick()` 按观察窗推进到 50% 和 100%。观察期间出现指定严重级别告警会停批并自动回滚。

## 4. `Sha256FormatVerifier` 类

```cpp
class Sha256FormatVerifier : public IArtifactVerifier
```

### 4.1 `verify()`

```cpp
bool verify(const Artifact& a, std::string& reason) override
```

**输入：** 制品只读引用和失败原因输出引用。

**输出：** 通过返回 `true`，失败返回 `false` 并填写原因。

**检查顺序：**

1. `artifact_id` 必须以 `os2.` 或 `qt.` 开头。
2. id 长度不能超过 128。
3. id 只允许字母、数字、点、下划线和连字符。
4. `sha256` 必须恰好 64 个字符。
5. 摘要每个字符必须是十六进制字符。
6. `version` 不能为空。

**失败原因：**

| 条件 | 原因 |
|---|---|
| 前缀错误 | `artifact_id must use unified code prefix (os2./qt.)` |
| id 过长 | `artifact_id too long (>128)` |
| id 字符非法 | `artifact_id has illegal char...` |
| 摘要长度错误 | `sha256 must be 64 hex chars` |
| 摘要不是十六进制 | `sha256 not hex` |
| 版本为空 | `version required` |

**状态变化：** 无。

## 5. `ArtifactSealer` 结构体

这是无成员状态的摘要工具类，两个函数都是 `static`。

### 5.1 `seal()`

```cpp
static std::string seal(const std::string& content)
```

**输入：** 制品原始内容。

**输出：** 64 位小写 SHA-256 十六进制字符串。

**状态变化：** 无。

### 5.2 `verify_content()`

```cpp
static bool verify_content(const Artifact& a, const std::string& content)
```

**输入：** 制品元数据和待复核内容。

**输出：** 重新计算的摘要与 `a.sha256` 完全相同返回 `true`，否则返回 `false`。

**注意：** 这里是区分大小写的直接比较；`artifact_receiver.hpp` 的真实文件路径则会先把摘要转小写。

## 6. `GrayscaleStore` 类

```cpp
class GrayscaleStore : public StoreService
```

### 6.1 继承构造函数

```cpp
using StoreService::StoreService;
```

让 `GrayscaleStore` 直接复用 `StoreService(ServiceIdentity, ServiceContext)`。

### 6.2 `rollout_log()`

```cpp
const std::vector<std::string>& rollout_log() const
```

**输入：** 无。

**输出：** 灰度记录数组的只读引用。

**状态变化：** 无。

主要供测试和观测查询使用。

### 6.3 `rollout_in_flight()`

```cpp
bool rollout_in_flight() const
```

**输入：** 无。

**输出：** staged 灰度是否正在进行。

## 7. `on_init()`

```cpp
bool on_init() override
```

**调用者：** `Os2Service::init()`。

**输入：** 无显式参数。

**输出：** 初始化成功返回 `true`，父类初始化失败返回 `false`。

**步骤：**

1. 先调用 `StoreService::on_init()`，建立发布和激活处理器。
2. 读取 `store.rollout_mode`，默认 `immediate`。
3. staged 模式下订阅 `topics::AlarmEvent`。

**状态变化：** 设置 `staged_`，可能增加告警订阅。

## 8. `make_verifier()`

```cpp
std::unique_ptr<IArtifactVerifier> make_verifier() override
```

**调用者：** `StoreService::on_init()`，通过虚函数分派到这里。

**输出：** 摘要格式校验器，或格式加签名的组合校验器。

**逻辑：**

```text
创建 Sha256FormatVerifier
    ↓
security.sig_algo != x509
    → 直接返回格式校验器

security.sig_algo == x509
    → 创建 OpensslSignatureCheck
    → 创建 SignatureArtifactVerifier
    → 返回组合校验器
```

**配置：**

| 配置项 | 用途 | 默认值 |
|---|---|---|
| `security.sig_algo` | 是否启用 x509 | 非 x509 时关闭 |
| `store.sign_dir` | 签名材料目录 | `deploy/certs` |
| `store.ca_bundle` | CA 文件 | 空时使用签名目录中的 `ca.crt` |
| `store.verify_script` | 验签脚本 | `tools/verify_artifact.sh` |

## 9. `on_activated()`

```cpp
void on_activated(const Artifact& a) override
```

**调用者：** `StoreService::handle_activation()`。

**输入：** 已经切换为 `activated` 的制品。

**输出：** 无。

### immediate 分支

遍历 `kBatches`，依次调用 `push_batch()` 记录 10%、50%、100%，然后返回。

### staged 分支

1. 保存当前 id 和版本。
2. `batch_idx_ = 0`。
3. 记录批次开始时间。
4. `in_flight_ = true`。
5. 推送首批 10%。

## 10. `on_tick()`

```cpp
void on_tick(std::uint64_t now) override
```

**调用者：** `Os2Service::tick(now)`。

**输入：** 当前毫秒时间。

**输出：** 无。

**步骤：**

1. 无论灰度状态如何，先调用 `persist_tick(now)`。
2. 没有在灰度时直接返回。
3. 观察窗未满时直接返回。
4. 批次索引加一。
5. 更新时间并推送下一批。
6. 到达最后一批时结束灰度并发布 `rollout_completed` 事件。

**配置：** `store.rollout_step_ms`，默认 2000ms。

**状态变化：** 修改 `batch_idx_`、`batch_start_` 和 `in_flight_`。

## 11. `gate_on_alarm()`

```cpp
void gate_on_alarm(const Event& e)
```

**访问权限：** `private`。

**调用者：** staged 模式订阅的 `AlarmEvent` 回调。

**输入：** 一个告警事件。

**输出：** 无。

**忽略条件：**

- 当前没有灰度进行。
- 事件级别为空。
- 告警来源是应用商店自己。
- 事件级别不在停止级别配置中。

**触发停批时：**

1. 先设置 `in_flight_ = false`，防止重复触发。
2. 在 `rollout_` 添加 halted 记录。
3. 发布 `rollout_halted` 事件。
4. 构造 `rollback` 命令。
5. 通过 `ActivationCommand` 请求自己执行回滚。
6. 回滚失败时发布 `rollout_rollback_failed` 事件。

**配置：**

- `store.rollout_halt_levels`，默认 `error,critical`。
- `store.rollback_subject`，默认当前服务 id。

**重要设计：** 自动回滚不直接修改制品状态，而是走与人工回滚相同的策略检查和审计路径。

## 12. `push_batch()`

```cpp
void push_batch(const std::string& id, const std::string& ver, int pct)
```

**输入：** 制品 id、版本和批次百分比。

**输出：** 无。

**行为：**

1. 添加形如 `id@version -> 50%` 的灰度日志。
2. 上报 `store.rollout_pct` 指标。

**状态变化：** `rollout_` 新增一项，并向管理总线发布指标。

## 13. 成员变量

| 成员 | 初始值 | 作用 |
|---|---:|---|
| `kBatches` | `{10, 50, 100}` | 固定灰度批次 |
| `rollout_` | 空 | 灰度过程记录 |
| `staged_` | `false` | 是否 staged 模式 |
| `in_flight_` | `false` | 是否正在灰度 |
| `cur_id_` | 空 | 当前制品 id |
| `cur_ver_` | 空 | 当前制品版本 |
| `batch_idx_` | `0` | 当前批次索引 |
| `batch_start_` | `0` | 当前观察窗开始时间 |

## 14. 灰度状态变化

```text
未开始
  in_flight=false
      ↓ activate(staged)
10%  in_flight=true, batch_idx=0
      ↓ 观察窗
50%  in_flight=true, batch_idx=1
      ↓ 观察窗
100% in_flight=false, batch_idx=2
```

任一观察窗中出现严重告警：

```text
in_flight=true
    ↓ error/critical
in_flight=false
    ↓ ActivationCommand rollback
Artifact.status=rolled-back
```

## 15. 函数总表

| 类 | 函数 | 输入 | 输出 | 作用 |
|---|---|---|---|---|
| `Sha256FormatVerifier` | `verify()` | 制品、原因 | `bool` | 严格格式准入 |
| `ArtifactSealer` | `seal()` | 内容 | SHA-256 | 制品封签 |
| `ArtifactSealer` | `verify_content()` | 制品、内容 | `bool` | 内容复核 |
| `GrayscaleStore` | `rollout_log()` | 无 | 日志只读引用 | 查询灰度记录 |
| `GrayscaleStore` | `rollout_in_flight()` | 无 | `bool` | 查询灰度状态 |
| `GrayscaleStore` | `on_init()` | 无 | `bool` | 初始化模式和告警订阅 |
| `GrayscaleStore` | `make_verifier()` | 配置 | 校验器 | 组装格式和签名校验 |
| `GrayscaleStore` | `on_activated()` | 制品 | 无 | 启动灰度 |
| `GrayscaleStore` | `on_tick()` | 当前时间 | 无 | 持久化和批次推进 |
| `GrayscaleStore` | `gate_on_alarm()` | 告警 | 无 | 停批并自动回滚 |
| `GrayscaleStore` | `push_batch()` | id、版本、百分比 | 无 | 记录并上报批次 |

## 16. 你的任务边界

这个文件不是你当前主要修改点，但你的 `ReceivingStore` 继承它，并使用它生成内层校验器。接收制品改动必须继续兼容：

- id 和摘要格式校验。
- 可选 X.509 签名。
- immediate/staged 灰度。
- 告警回滚。
- 状态持久化。

## 17. 阅读时最应该记住的三点

1. `make_verifier()` 决定制品进入文件接收前必须通过哪些检查。
2. immediate 一次记录三批，staged 由 `tick()` 按时间推进。
3. 自动回滚仍走 `ActivationCommand` 和 `PolicyCheck`，不会绕过安全审计。
