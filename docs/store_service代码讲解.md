# `store_service.hpp` 代码讲解

源码：`/home/haoran/os-module/modules/appstore-portal/src/store_service.hpp`

## 1. 文件的总体职责

`store_service.hpp` 定义应用商店与软件仓的公共服务骨架 `StoreService`。

它统一处理：

- 接收制品发布请求。
- 调用制品校验器。
- 在内存中登记制品元数据。
- 接收制品激活或回滚命令。
- 在高影响操作前请求安全策略检查。
- 把制品状态保存到文件。
- 服务重启时恢复制品状态。
- 为灰度发布和真实文件接收提供扩展点。

这个文件不负责服务注册中心。注册、心跳和公共生命周期由父类 `Os2Service` 负责。

应用商店的继承关系是：

```text
Os2Service
    ↓ 继承
StoreService
    ↓ 继承
GrayscaleStore
    ↓ 继承
ReceivingStore
```

各层职责：

| 类 | 职责 |
|---|---|
| `Os2Service` | 生命周期、服务注册、心跳、总线、配置、日志 |
| `StoreService` | 发布、登记、激活、回滚、状态持久化 |
| `GrayscaleStore` | SHA-256 格式、签名、灰度推进 |
| `ReceivingStore` | 真实制品文件校验和原子入库 |

---

## 2. 一次发布请求的完整流程

```text
上游发送 ArtifactPublish
    ↓
管理总线调用 handle_publish(m)
    ↓
从 Msg 中读取 id、版本、摘要和 SBOM
    ↓
构造 Artifact
    ↓
verifier_->verify(artifact, reason)
    ├─ 失败：返回 accepted=false 和原因
    └─ 成功：继续
    ↓
artifacts_[artifact_id] = artifact
    ↓
state_dirty_ = true
    ↓
记录 artifact_published 日志
    ↓
返回 accepted=true
```

当实际运行对象是 `ReceivingStore` 时，`verifier_` 最终指向 `FilesystemArtifactVerifier`。因此真实文件校验和入库发生在登记元数据之前。

---

## 3. 本文件使用的关键数据类型

### 3.1 `Artifact`

`Artifact` 定义在 `include/os2/appstore_portal/api.hpp`，表示一条制品记录。

| 字段 | 类型 | 含义 | 来源 |
|---|---|---|---|
| `artifact_id` | `std::string` | 制品唯一编号 | 发布请求 |
| `version` | `std::string` | 制品版本 | 发布请求 |
| `sha256` | `std::string` | 内容摘要 | 发布请求 |
| `sbom_ref` | `std::string` | SBOM 引用 | 发布请求 |
| `status` | `std::string` | 制品状态 | 服务内部设置 |
| `published_ms` | `std::uint64_t` | 发布时间 | `now_ms()` |

状态可能是：

```text
published
activated
rolled-back
```

### 3.2 `IArtifactVerifier`

这是所有制品校验器必须实现的接口：

```cpp
virtual bool verify(const Artifact& a, std::string& reason) = 0;
```

输入是待校验制品，输出是布尔结果。失败时通过 `reason` 引用参数返回原因。

### 3.3 `Msg`

`Msg` 是管理总线使用的通用消息：

```cpp
struct Msg {
  std::string type;
  std::map<std::string, std::string> kv;
};
```

- `type`：消息类型。
- `kv`：字段表。
- `get(key)`：读取一个字符串字段，字段不存在时返回空字符串。

### 3.4 `Command` 与 `Reply`

激活和回滚请求会从 `Msg` 转换为 `Command`，处理结果再由 `Reply` 转换回 `Msg`。

`Command` 中本文件主要使用：

- `target_id`
- `command_type`
- `operator_id`
- `trace_id`

`Reply` 中主要返回：

- `result`
- `reason_code`
- `current_state`
- `timestamp`
- `trace_id`

---

## 4. `DigestVerifier` 类

```cpp
class DigestVerifier : public IArtifactVerifier
```

### 4.1 类的作用

它是 `StoreService` 默认使用的最低限度校验器，只检查 `sha256` 字段是否为空。

它不检查：

- 摘要是不是 64 位十六进制。
- 摘要是否与真实文件一致。
- 制品签名。
- SBOM 内容。
- 版本兼容性。

这些严格检查由后续派生类加入。

### 4.2 `verify()`

```cpp
bool verify(const Artifact& a, std::string& reason) override
```

**访问权限：** `public`。

**调用者：** `StoreService::handle_publish()` 通过 `verifier_` 调用。

**输入：**

| 参数 | 类型 | 含义 |
|---|---|---|
| `a` | `const Artifact&` | 待校验制品，只读引用 |
| `reason` | `std::string&` | 输出参数，失败时接收原因 |

**输出：**

| 返回值 | 含义 | `reason` |
|---|---|---|
| `true` | `sha256` 非空 | 不保证修改 |
| `false` | `sha256` 为空 | `missing sha256` |

**状态变化：** 无。

---

## 5. `StoreService` 类

```cpp
class StoreService : public Os2Service
```

### 5.1 类的作用

`StoreService` 是应用商店的公共服务骨架。它从 `Os2Service` 获得：

- `init()`、`start()`、`tick()`、`stop()`。
- `mgmt()` 管理总线。
- `biz()` 业务总线。
- `config()` 配置。
- `log()` 日志。
- `identity()` 服务身份。
- `emit_event()` 和 `emit_metric()`。

它自己维护一个内存制品目录，并提供发布、激活、回滚和持久化能力。

---

## 6. `StoreService` 的 public 函数

### 6.1 构造函数

```cpp
StoreService(ServiceIdentity id, ServiceContext ctx)
    : Os2Service(std::move(id), std::move(ctx)) {}
```

**输入：**

| 参数 | 类型 | 含义 |
|---|---|---|
| `id` | `ServiceIdentity` | 应用商店的服务身份 |
| `ctx` | `ServiceContext` | 双总线和配置 |

**输出：** 构造函数没有返回值，构造完成后得到一个 `StoreService` 对象。

**内部行为：**

1. 把 `id` 和 `ctx` 移交给父类 `Os2Service`。
2. 父类生成缺失的实例编号。
3. 父类创建日志器。
4. 父类生命周期状态设为 `Created`。

**本类成员的初始状态：**

```text
verifier_          = 空
artifacts_         = 空 map
rollback_point_    = 空字符串
state_dirty_       = false
last_persist_ms_   = 0
```

### 6.2 `find()`

```cpp
std::optional<Artifact> find(const std::string& id) const
```

**访问权限：** `public`。

**调用者：** 测试、查询接口或需要检查制品状态的上层代码。

**输入：** `id`，要查询的 `artifact_id`。

**输出：**

| 结果 | 含义 |
|---|---|
| `optional` 中有值 | 找到制品，返回一份 `Artifact` 副本 |
| `std::nullopt` | 没有找到 |

**内部步骤：**

1. 调用 `artifacts_.find(id)`。
2. 迭代器等于 `artifacts_.end()` 时返回 `nullopt`。
3. 否则返回 `it->second`。

**状态变化：** 无。函数末尾的 `const` 表示它不修改当前对象。

---

## 7. `StoreService` 的 protected 扩展点

这些函数可由派生类调用或重写，普通外部代码不能直接调用。

### 7.1 `on_init()`

```cpp
bool on_init() override
```

**调用者：** 父类 `Os2Service::init()`。

**输入：** 无。

**输出：** 当前实现返回 `true`，表示初始化成功。

**内部步骤：**

1. 调用 `make_verifier()` 创建校验器。
2. 调用 `restore_state()` 恢复历史状态。
3. 使用 `mgmt().serve()` 注册 `ArtifactPublish` 处理器。
4. 使用 `mgmt().serve()` 注册 `ActivationCommand` 处理器。

注册后形成：

```text
ArtifactPublish
    → handle_publish(m)
    → ArtifactPublishReply

ActivationCommand
    → handle_activation(m)
    → Reply
```

**状态变化：**

- `verifier_` 获得校验器对象。
- `artifacts_` 和 `rollback_point_` 可能被恢复。
- 管理总线增加两个请求处理器。

**失败情况：** 当前实现不主动返回失败；持久化文件不存在时按空状态继续。

### 7.2 `on_stop()`

```cpp
void on_stop() override
```

**调用者：** 父类 `Os2Service::stop()`。

**输入/输出：** 无。

**内部行为：** 调用 `persist_state(true)`，在停止前强制尝试保存一次状态。

**失败情况：** 写盘失败时记录警告，不抛出异常。

### 7.3 `persist_tick()`

```cpp
void persist_tick(std::uint64_t now)
```

**调用者：** `GrayscaleStore::on_tick(now)`。

**输入：** `now`，当前毫秒时间。

**输出：** 无。

**配置输入：**

```text
store.persist_ms
```

默认保存周期为 1000ms。

**执行流程：**

```text
now - last_persist_ms_ < persist_ms
    → 直接返回

到达保存周期
    → last_persist_ms_ = now
    → persist_state(false)
```

**状态变化：** 更新 `last_persist_ms_`；保存成功时清除 `state_dirty_`。

### 7.4 `make_verifier()`

```cpp
virtual std::unique_ptr<IArtifactVerifier> make_verifier()
```

**调用者：** `StoreService::on_init()`。

**输入：** 无显式参数。

**输出：** 一个由 `StoreService` 独占的 `IArtifactVerifier` 智能指针。

**基类输出：**

```cpp
std::make_unique<DigestVerifier>()
```

**派生类重写：**

- `GrayscaleStore` 返回 SHA-256 格式和可选签名校验链。
- `ReceivingStore` 返回包含真实文件校验和入库功能的校验链。

**设计意义：** 不修改 `handle_publish()`，就能替换整个校验策略。

### 7.5 `on_activated()`

```cpp
virtual void on_activated(const Artifact&) {}
```

**调用者：** `handle_activation()` 在状态改为 `activated` 后调用。

**输入：** 激活后的 `Artifact` 只读引用。

**输出：** 无。

**基类行为：** 空操作。

**派生类行为：** `GrayscaleStore` 重写它，启动 10%、50%、100% 灰度推进。

---

## 8. `StoreService` 的 private 函数

### 8.1 `handle_publish()`

```cpp
Msg handle_publish(const Msg& m)
```

**调用者：** 管理总线收到 `topics::ArtifactPublish` 请求时调用。

**输入消息字段：**

| 字段 | 含义 |
|---|---|
| `artifact_id` | 制品编号 |
| `version` | 制品版本 |
| `sha256` | 摘要 |
| `sbom_ref` | SBOM 引用 |

**内部生成：**

- `status = "published"`
- `published_ms = now_ms()`

**内部步骤：**

1. 从 `Msg` 读取字段并构造 `Artifact`。
2. 检查 `artifact_id` 是否为空。
3. 调用 `verifier_->verify(a, reason)`。
4. 校验失败时返回拒绝消息。
5. 校验成功时写入 `artifacts_`。
6. 设置 `state_dirty_ = true`。
7. 写 `artifact_published` 日志。
8. 返回成功消息。

**成功输出：**

```cpp
Msg{"ArtifactPublishReply", {{"accepted", "true"}}}
```

**失败输出：**

```cpp
Msg{
  "ArtifactPublishReply",
  {{"accepted", "false"}, {"reason", reason}}
}
```

**失败条件：**

- `artifact_id` 为空。
- 当前校验链拒绝制品。

**状态变化：**

- 成功时新增或覆盖 `artifacts_[artifact_id]`。
- 成功时把 `state_dirty_` 设为 `true`。

**现有代码细节：** `artifact_id` 为空时没有主动给 `reason` 赋值，因此失败原因可能为空字符串。

### 8.2 `handle_activation()`

```cpp
Msg handle_activation(const Msg& m)
```

**调用者：** 管理总线收到 `topics::ActivationCommand` 请求时调用。

**输入：** 通用 `Msg`，通过 `command_from(m)` 解析为 `Command`。

主要使用字段：

| 字段 | 含义 |
|---|---|
| `target_id` | 目标制品编号 |
| `command_type` | `activate` 或 `rollback` |
| `operator_id` | 操作者 |
| `trace_id` | 链路追踪编号 |

**内部步骤：**

1. 在 `artifacts_` 中查找目标制品。
2. 找不到时返回 `SVC_NOT_REGISTERED`。
3. 构造 `PolicyRequest`。
4. 请求 `topics::PolicyCheck`，超时 500ms。
5. 无响应或 `allow != "true"` 时返回 `SEC_DENIED`。
6. `activate` 时把状态改为 `activated`，再调用 `on_activated()`。
7. `rollback` 时把状态改为 `rolled-back`。
8. 其他命令返回 `SCH_CHAIN_INVALID`。
9. 成功后设置脏标记、写日志并返回成功结果。

**发送给策略服务的输入：**

| 字段 | 值 |
|---|---|
| `subject` | `operator_id` |
| `action` | `artifact.activate` 或 `artifact.rollback` |
| `target` | `target_id` |
| `trace_id` | 原命令追踪号 |

**成功输出：** 标准 `Reply` 消息，其中：

- `result = "success"`
- `reason_code = OS2-0000`
- `current_state = "activated"` 或 `"rolled-back"`

**失败输出：**

| 情况 | 错误码 | 返回状态 |
|---|---|---|
| 制品不存在 | `SVC_NOT_REGISTERED` | `unknown-artifact` |
| 策略拒绝或超时 | `SEC_DENIED` | 制品原状态 |
| 命令类型非法 | `SCH_CHAIN_INVALID` | 制品原状态 |

**状态变化：**

- 修改目标制品状态。
- 可能修改 `rollback_point_`。
- 成功时设置 `state_dirty_ = true`。
- 激活时可能由派生类启动灰度流程。

### 8.3 `persist_state()`

```cpp
void persist_state(bool force)
```

**调用者：** `persist_tick()` 和 `on_stop()`。

**输入：**

| `force` | 含义 |
|---|---|
| `false` | 只在 `state_dirty_ == true` 时保存 |
| `true` | 即使状态未变也尝试保存 |

**配置输入：** `store.persist_path`。

**输出：** 无。

**提前返回：**

- 未配置持久化路径。
- 非强制保存且状态没有变化。

**文件格式：** TSV 文本。

制品行：

```text
A\t制品ID\t版本\tSHA256\tSBOM\t状态\t发布时间
```

回滚点行：

```text
R\t制品ID
```

**写入方式：** `atomic_write()` 先写临时文件再原子替换，避免留下半个状态文件。

**成功后的状态变化：** `state_dirty_ = false`。

**失败输出：** 没有返回值，但记录 `store_persist_failed` 警告，且保留脏标记供以后重试。

### 8.4 `restore_state()`

```cpp
void restore_state()
```

**调用者：** `on_init()`。

**输入：** 从 `store.persist_path` 指向的文件读取。

**输出：** 无。

**内部步骤：**

1. 路径为空时直接返回。
2. 文件不存在或无法打开时直接返回。
3. 使用 `getline()` 逐行读取。
4. 按制表符拆分字段。
5. 两列 `R` 行恢复 `rollback_point_`。
6. 七列 `A` 行恢复一个 `Artifact`。
7. 使用 `strtoull()` 把发布时间转回整数。
8. 恢复到制品时记录 `store_restored` 日志。

**状态变化：** 填充 `artifacts_` 和 `rollback_point_`。

**异常输入：** 列数或记录类型不正确的行会被忽略。

---

## 9. 成员变量

| 成员 | 类型 | 初始值 | 作用 |
|---|---|---:|---|
| `verifier_` | `unique_ptr<IArtifactVerifier>` | 空 | 当前制品校验链 |
| `artifacts_` | `map<string, Artifact>` | 空 | 内存制品目录 |
| `rollback_point_` | `string` | 空 | 回滚目标制品编号 |
| `state_dirty_` | `bool` | `false` | 是否有尚未写盘的修改 |
| `last_persist_ms_` | `uint64_t` | `0` | 上次周期保存时间 |

### `verifier_`

`unique_ptr` 表示校验器由 `StoreService` 独占。服务销毁时会自动释放，不需要手工 `delete`。

### `artifacts_`

键是 `artifact_id`，值是 `Artifact`。发布、激活、回滚和状态恢复都会操作它。

### `state_dirty_`

发布、激活或回滚成功后变为 `true`；状态文件保存成功后恢复为 `false`。

---

## 10. 两类请求的输入输出

### 10.1 `ArtifactPublish`

**输入示例：**

```cpp
Msg{
  "ArtifactPublish",
  {
    {"artifact_id", "os2.pkg.demo"},
    {"version", "1.0.0"},
    {"sha256", "64位摘要"},
    {"sbom_ref", "sbom://demo"}
  }
}
```

**成功输出：**

```cpp
Msg{"ArtifactPublishReply", {{"accepted", "true"}}}
```

**失败输出：**

```cpp
Msg{
  "ArtifactPublishReply",
  {{"accepted", "false"}, {"reason", "失败原因"}}
}
```

### 10.2 `ActivationCommand`

**输入核心字段：**

```text
command_id
target_id
command_type
operator
trace_id
```

**输出核心字段：**

```text
command_id
result
reason_code
current_state
timestamp
trace_id
```

---

## 11. 校验器的逐层组合

```text
DigestVerifier
    只检查 sha256 非空

Sha256FormatVerifier
    检查 id、版本、64 位十六进制摘要

SignatureArtifactVerifier（按配置启用）
    检查证书链、有效期和签名

FilesystemArtifactVerifier
    检查真实文件、大小、真实摘要和同版本不可替换
    校验成功后原子写入仓库
```

最终 `ReceivingStore::make_verifier()` 把这些能力组合成一条校验链。

---

## 12. 与接收制品功能的关系

你的接收制品代码没有重新实现发布流程，而是重写 `make_verifier()`：

```text
StoreService::handle_publish()
    ↓
verifier_->verify()
    ↓ 实际对象是 FilesystemArtifactVerifier
检查元数据格式
    ↓
检查暂存文件
    ↓
限制文件大小
    ↓
计算真实 SHA-256
    ↓
检查同版本是否已存在
    ↓
原子写入 repository
    ↓
返回 handle_publish()
    ↓
登记制品元数据
```

`handle_publish()` 是 `private`，说明派生类不能也不需要重写公共发布流程。

---

## 13. 函数总表

| 类 | 函数 | 输入 | 输出 | 主要作用 |
|---|---|---|---|---|
| `DigestVerifier` | `verify(a, reason)` | 制品、原因引用 | `bool` | 检查摘要是否为空 |
| `StoreService` | 构造函数 | 身份、上下文 | 服务对象 | 初始化父类和成员 |
| `StoreService` | `find(id)` | 制品编号 | `optional<Artifact>` | 查询制品 |
| `StoreService` | `on_init()` | 无 | `bool` | 创建校验器、恢复状态、注册处理器 |
| `StoreService` | `on_stop()` | 无 | 无 | 停止时强制保存 |
| `StoreService` | `persist_tick(now)` | 当前时间 | 无 | 按周期保存 |
| `StoreService` | `make_verifier()` | 无 | 校验器智能指针 | 创建可替换的校验链 |
| `StoreService` | `on_activated(a)` | 激活制品 | 无 | 激活后的扩展钩子 |
| `StoreService` | `handle_publish(m)` | 发布消息 | 回复消息 | 校验并登记制品 |
| `StoreService` | `handle_activation(m)` | 激活/回滚消息 | 回复消息 | 权限检查并切换状态 |
| `StoreService` | `persist_state(force)` | 是否强制 | 无 | 原子保存状态 |
| `StoreService` | `restore_state()` | 配置中的文件 | 无 | 恢复制品和回滚点 |

---

## 14. 你的任务边界

### 需要理解，不应修改

- `Os2Service` 的服务注册、心跳和生命周期。
- `StoreService` 的公共发布、激活、回滚和持久化框架。

### 当前重点开发和维护

- `modules/appstore-portal/src/impl/artifact_receiver.hpp`
- `modules/appstore-portal/tests/test_artifact_receiver.cpp`

### 联调时需要确认

- 上游如何把真实制品写入暂存目录。
- `artifact_id`、`version`、`sha256` 和 `sbom_ref` 是否完整。
- `store.incoming_dir` 的实际配置。
- `store.repository_dir` 的实际配置。
- `store.max_artifact_bytes` 的产品限制。
- 校验失败原因是否符合接口约定。

## 15. 阅读时最应该记住的三点

1. `StoreService` 管公共流程，`ReceivingStore` 通过校验器扩展真实文件接收。
2. 制品必须先通过 `verifier_->verify()`，才能登记到 `artifacts_`。
3. 你当前主要修改 `artifact_receiver.hpp` 和对应测试，不需要修改服务注册或公共生命周期。
