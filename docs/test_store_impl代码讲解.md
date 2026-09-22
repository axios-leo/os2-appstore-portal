# `test_store_impl.cpp` 代码讲解

源码：`/home/haoran/os-module/modules/appstore-portal/tests/test_store_impl.cpp`

## 1. 文件的总体职责

这个文件验证应用商店增强实现 `GrayscaleStore`：

- 严格 SHA-256 格式。
- 统一制品 id 前缀和字符白名单。
- 内容封签与篡改检测。
- X.509 签名校验组合逻辑。
- immediate 和 staged 两种灰度模式。
- 告警触发停批和自动回滚。
- 外部验签命令的注入防护。
- 制品状态跨重启持久化。

它位于基础服务测试与真实文件接收测试之间。

## 2. 被测代码关系

```text
StoreService
    ↓
GrayscaleStore
    ├─ Sha256FormatVerifier
    ├─ ArtifactSealer
    ├─ SignatureArtifactVerifier
    ├─ 灰度推进
    ├─ 告警健康门控
    └─ 状态持久化
```

## 3. 依赖

| 依赖 | 作用 |
|---|---|
| `<sys/stat.h>` | 创建注入测试目录 |
| `<cstdio>` | 删除测试文件 |
| `<fstream>` | 写假验签脚本、读取哨兵文件 |
| `grayscale_store.hpp` | 被测灰度商店和摘要工具 |
| `signature_verifier.hpp` | 签名验证器与真实后端 |
| `testing.hpp` | 测试框架 |

## 4. `sha_format_enforced_and_grayscale_rollout`

### 测试目标

验证错误摘要被拒绝，以及 immediate 模式激活后立即记录 10%、50%、100% 三批。

### 输入

- 错误摘要：`zz!`
- 正确 id：`qt.pkg.app`
- 正确摘要：`ArtifactSealer::seal("app-1.0-content")`
- 策略检查固定放行

### 执行步骤与输出

1. 创建并启动 `GrayscaleStore`。
2. 发布错误摘要，期望 `accepted=false`。
3. 发布 64 位真实摘要。
4. 发送激活命令，期望成功。
5. 期望 `rollout_log().size() == 3`。
6. 最后一条记录必须包含 `100%`。

### 覆盖函数

- `Sha256FormatVerifier::verify()`
- `ArtifactSealer::seal()`
- `GrayscaleStore::on_activated()` immediate 分支
- `GrayscaleStore::push_batch()`

## 5. `strict_digest_and_sealer`

### 测试目标

单独验证格式校验器和内容封签工具。

### 场景与输出

| 场景 | 输入 | 期望 |
|---|---|---|
| 摘要过短 | `abcd1234` | 拒绝 |
| id 无统一前缀 | `pkg-x` | 拒绝 |
| 合法制品 | `qt.pkg.x` + 真实摘要 | 接受 |
| 原内容复核 | 原始内容 | `true` |
| 篡改内容复核 | 原内容加 `x` | `false` |

### 状态变化

无。这里直接测试纯校验逻辑，不创建服务。

## 6. 签名测试辅助类型

### 6.1 `PassInner`

```cpp
struct PassInner : IArtifactVerifier
```

它模拟内层格式校验器。

`verify()` 输入制品和原因引用，固定输出 `true`。这样签名测试只关注外层签名逻辑。

### 6.2 `FakeSig`

```cpp
struct FakeSig : ISignatureCheck
```

成员：

- `ok`：控制校验成功或失败。
- `last_id`：记录后端收到的制品 id。

构造函数输入一个布尔值并保存到 `ok`。

`check(id, digest, reason)`：

- 输入制品 id、摘要和原因引用。
- 保存 `last_id`。
- `ok=false` 时写入 `fake reject`。
- 返回 `ok`。

### 6.3 `mk()`

无输入，输出一个合法的测试 `Artifact`：

```text
id      = os2.pkg.x
version = 1.0
sha256  = 64 个 a
status  = published
```

## 7. `x509_verifier_accepts_when_signature_ok`

### 测试目标

验证内层校验通过且签名后端通过时，组合校验器接受制品。

### 输入

- `PassInner`：固定通过。
- `FakeSig(true)`：签名固定通过。
- `enabled=true`：启用签名检查。

### 输出

- `v.verify(a, why) == true`
- `raw->last_id == "os2.pkg.x"`

第二个断言证明签名后端确实被调用，而不是被错误跳过。

## 8. `x509_verifier_rejects_when_signature_bad`

输入 `FakeSig(false)` 和 `enabled=true`。

期望：

- `verify()` 返回 `false`。
- 原因包含 `fake reject`。

它验证签名失败会阻止制品准入。

## 9. staged 灰度辅助函数

### 9.1 `make_staged_store()`

**输入：** `ServiceContext&`。

**输出：** `GrayscaleStore`。

**行为：** 注册固定放行的策略桩，再创建灰度商店。

### 9.2 `publish_and_activate()`

**输入：** `ServiceContext&`。

**输出：** 无；内部断言激活回复成功。

**行为：** 发布 `qt.pkg.app@2.0`，再发送激活命令。

## 10. `staged_rollout_advances_per_observation_window`

### 测试目标

验证 staged 模式必须等待观察窗，不能一次完成三批。

### 配置输入

```text
store.rollout_mode    = staged
store.rollout_step_ms = 100
```

### 执行时间线

```text
激活          → 10%，in_flight=true
t0 + 50ms     → 窗口未满，不推进
t0 + 150ms    → 50%
t0 + 300ms    → 100%，in_flight=false
t0 + 999ms    → 已完成，不再增长
```

### 输出断言

- 最终恰好三条灰度记录。
- 灰度流程完成。
- 制品状态仍为 `activated`。

## 11. `staged_rollout_halted_by_alarm_and_rolled_back`

### 测试目标

验证观察窗内严重告警会停止灰度并自动回滚。

### 输入与输出

1. 激活后处于 10% 灰度进行中。
2. 发布 `info` 告警：不触发门控，仍在灰度。
3. 发布 `error` 告警：停止灰度并发送回滚命令。
4. 期望制品状态为 `rolled-back`。
5. 灰度日志包含 `halted@10%`。
6. 后续 `tick()` 不再推进。

### 覆盖函数

- `GrayscaleStore::gate_on_alarm()`
- 自动构造 `rollback` 命令
- `StoreService::handle_activation()` 回滚分支

## 12. `x509_disabled_is_format_only`

### 测试目标

验证签名功能关闭时，只运行内层校验，不调用签名后端。

### 输入

- `PassInner`：通过。
- `FakeSig(false)`：如果被调用会失败。
- `enabled=false`。

### 输出

- 总体验证成功。
- `last_id` 为空，证明签名后端没有被调用。

## 13. `artifact_id_charset_whitelist_blocks_shell_metachars`

### 测试目标

验证制品 id 字符白名单，阻止命令注入和路径穿越字符进入后续流程。

### 拒绝输入

```text
os2.x';rm -rf x'
qt.pkg app
os2.a$(x)
qt.pkg"q"
os2.a/../../etc
```

以上每项都必须得到 `accepted=false`。

### 接受输入

```text
qt.pkg.app-2_1
```

它只包含允许的字母、数字、点、下划线和连字符，期望 `accepted=true`。

## 14. `x509_backend_de_shelled_resists_command_injection`

### 测试目标

验证真实 `OpensslSignatureCheck` 使用参数数组调用脚本，而不是把外部输入拼成 shell 命令。

### 准备过程

1. 创建 `/tmp/os2_f06_deshell_test`。
2. 写一个固定退出码为 0 的假验签脚本。
3. 删除可能遗留的 `PWNED` 哨兵文件。
4. 构造包含 `touch PWNED` 的恶意制品 id。

### 输入

```text
a'; touch /tmp/.../PWNED; echo '
```

### 期望输出

调用 `check()` 后，`PWNED` 文件不存在。

这说明恶意字符串只被当作普通参数，没有被 shell 执行。

## 15. `store_state_persists_and_restores_f07`

### 测试目标

验证制品元数据和激活状态能跨服务对象重建恢复。

### 配置输入

```text
store.persist_path = /tmp/os2_store_persist_test.tsv
store.persist_ms   = 0
```

### 第一阶段：写入

1. 删除旧状态文件。
2. 创建并启动第一个 `GrayscaleStore`。
3. 发布 `qt.pkg.app@1.0`。
4. 激活制品。
5. 调用 `s.stop()`，触发 `on_stop()` 强制落盘。

### 第二阶段：恢复

1. 使用相同配置创建第二个服务对象。
2. `init()` 调用 `restore_state()`。
3. 查询 `qt.pkg.app`。

### 输出断言

- 制品存在。
- 状态为 `activated`。
- 版本为 `1.0`。
- SBOM 为 `sbom://1`。

测试结束后删除状态文件。

## 16. `main()` 的位置

`main()` 写在第一个测试后面：

```cpp
int main() { return os2::testing::run_all(); }
```

后面的测试仍然会执行，因为每个 `OS2_TEST` 都通过静态 `Registrar` 在进入 `main()` 前注册。源代码书写位置不影响静态注册完成时间。

## 17. 测试用例总表

| 测试 | 验证目标 |
|---|---|
| `sha_format_enforced_and_grayscale_rollout` | 严格摘要和 immediate 灰度 |
| `strict_digest_and_sealer` | 摘要格式、封签、篡改检测 |
| `x509_verifier_accepts_when_signature_ok` | 签名成功 |
| `x509_verifier_rejects_when_signature_bad` | 签名失败 |
| `staged_rollout_advances_per_observation_window` | staged 观察窗推进 |
| `staged_rollout_halted_by_alarm_and_rolled_back` | 告警停批回滚 |
| `x509_disabled_is_format_only` | 签名关闭时兼容行为 |
| `artifact_id_charset_whitelist_blocks_shell_metachars` | id 字符白名单 |
| `x509_backend_de_shelled_resists_command_injection` | 外部命令注入防护 |
| `store_state_persists_and_restores_f07` | 状态持久化与恢复 |

## 18. 运行方式

```bash
cd /home/haoran/os-module
cmake --build build -j2
ctest --test-dir build -R '^test_store_impl$' --output-on-failure
```

## 19. 你的任务边界

这个文件主要验证灰度、签名和持久化，不是你当前接收制品任务的主要修改点。但你的 `FilesystemArtifactVerifier` 包装了这里的校验链，因此这些测试必须继续通过。

## 20. 阅读时最应该记住的三点

1. 这个文件验证 `GrayscaleStore` 的增强能力，不读取真实制品文件。
2. `FakeSig` 隔离真实证书环境，使签名决策测试稳定可重复。
3. 接收制品修改不能破坏摘要、签名、灰度和持久化的原有行为。
