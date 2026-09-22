# `test_artifact_receiver.cpp` 代码讲解

源码：`/home/haoran/os-module/modules/appstore-portal/tests/test_artifact_receiver.cpp`

## 1. 文件的总体职责

这个文件直接验证你负责的“接收制品”功能：

- 读取暂存目录中的真实制品文件。
- 重新计算文件 SHA-256。
- 摘要匹配时原子写入软件仓。
- 摘要不匹配时拒绝且不登记。
- 拒绝文件不存在、文件过大和危险版本路径。
- 相同内容重复提交时保持幂等。
- 阻止同一 id 和版本被不同内容替换。

## 2. 被测代码与调用关系

```text
test_artifact_receiver.cpp
    ↓ 创建 ReceivingStore
StoreService::handle_publish()
    ↓ 调用
FilesystemArtifactVerifier::verify()
    ↓ 包装
GrayscaleStore 的格式/签名校验器
    ↓ 成功后
原子写入 repository
    ↓ 返回
StoreService 登记元数据
```

测试不会直接调用私有 `handle_publish()`，而是通过管理总线发送 `ArtifactPublish`。

## 3. 依赖

| 头文件 | 用途 |
|---|---|
| `<filesystem>` | 创建目录、拼接路径、判断文件是否存在 |
| `<fstream>` | 写暂存文件、读取入库文件 |
| `<iterator>` | 一次读取完整文件内容 |
| `<string>` | 保存 id、版本、摘要和内容 |
| `artifact_receiver.hpp` | 被测 `ReceivingStore` 与文件校验器 |
| `testing.hpp` | 测试宏和运行器 |

## 4. 匿名命名空间

```cpp
namespace { ... }
```

其中的 `Fixture`、`make_store()` 和 `publish()` 只在当前 `.cpp` 文件可见，避免与其他测试文件重名。

## 5. `Fixture` 测试夹具

```cpp
struct Fixture
```

它为每个测试创建独立临时目录，并在测试结束时清理。

### 成员变量

| 成员 | 含义 |
|---|---|
| `root` | 本测试的唯一临时根目录 |
| `incoming` | 上游放置暂存制品的目录 |
| `repository` | 校验通过后制品进入的软件仓目录 |

### 5.1 构造函数 `Fixture()`

**输入：** 无。

**输出：** 构造一个夹具对象。

**内部步骤：**

1. 在 `/tmp` 下用 `gen_id()` 生成唯一目录。
2. 设置 `incoming` 路径。
3. 设置 `repository` 路径。
4. 创建 `incoming` 目录。

**状态变化：** 文件系统中新增临时目录。

### 5.2 析构函数 `~Fixture()`

```cpp
~Fixture() { std::filesystem::remove_all(root); }
```

**输入/输出：** 无。

**作用：** 测试函数结束时自动递归删除本测试产生的目录和文件。

这是 RAII：资源随对象创建，随对象销毁自动清理。

### 5.3 `config()`

```cpp
Config config(std::uint64_t max_bytes = 1024 * 1024) const
```

**输入：** `max_bytes`，允许的最大制品字节数；默认 1 MiB。

**输出：** 一个 `Config`，包含：

```text
store.incoming_dir
store.repository_dir
store.max_artifact_bytes
```

**状态变化：** 无。

### 5.4 `stage()`

```cpp
void stage(id, version, content) const
```

**输入：** 制品 id、版本、文件内容。

**输出：** 无返回值；在暂存目录创建文件。

文件名规则：

```text
<incoming>/<id>-<version>.artifact
```

文件使用二进制模式写入。

## 6. `make_store()`

```cpp
ReceivingStore make_store(ServiceContext& ctx)
```

**输入：** 测试上下文引用。

**输出：** 配置好的 `ReceivingStore` 对象。

**内部步骤：**

1. 注册固定返回 `allow=true` 的 `PolicyCheck` 测试桩。
2. 构造应用商店服务身份。
3. 返回 `ReceivingStore`。

策略桩对发布本身没有影响，但使需要策略的激活路径具备完整上下文。

## 7. `publish()`

```cpp
Msg publish(ServiceContext& ctx,
            const std::string& id,
            const std::string& version,
            const std::string& digest)
```

**输入：** 上下文、制品 id、版本和期望摘要。

**输出：** `ArtifactPublishReply` 消息。

**内部步骤：**

1. 构造带 `artifact_id/version/sha256/sbom_ref` 的发布消息。
2. 请求 `topics::ArtifactPublish`，超时 100ms。
3. 断言一定收到回复。
4. 返回回复内容。

这个辅助函数减少四个测试中重复的消息构造代码。

## 8. `receives_real_file_verifies_digest_and_persists_atomically`

### 测试目标

验证接收制品的成功路径。

### 输入

```text
id      = os2.pkg.demo
version = 1.0.0
content = real artifact bytes v1
sha256  = ArtifactSealer::seal(content)
```

### 执行步骤

1. 创建临时目录。
2. 把真实内容写入暂存文件。
3. 用夹具配置创建 `ReceivingStore`。
4. 初始化并启动服务。
5. 发送摘要正确的发布请求。
6. 检查回复、内存登记和仓库文件。

### 期望输出

- `accepted == true`
- `store.find(id)` 有值
- 文件存在于 `repository/id/version/artifact.bin`
- 入库文件内容与原始内容完全相同

### 覆盖的生产逻辑

- 暂存文件读取
- SHA-256 重算
- 目录创建
- `atomic_write()`
- 元数据登记

## 9. `rejects_tampered_file_without_registering_or_persisting`

### 测试目标

验证文件内容与请求摘要不一致时必须拒绝，而且不能留下部分结果。

### 输入

- 暂存文件内容：`tampered bytes`
- 请求摘要对应内容：`expected bytes`

两者计算出的 SHA-256 不同。

### 期望输出

- `accepted == false`
- 原因包含 `sha256 mismatch`
- `store.find(id)` 没有值
- 仓库中不存在 `artifact.bin`

这里同时验证失败的原子性：不能出现“文件失败但元数据已登记”的半成功状态。

## 10. `rejects_missing_oversized_and_unsafe_version_inputs`

这个测试包含三个失败场景。

### 场景一：暂存文件不存在

**输入：** 发布 `os2.pkg.missing@1.0`，但不调用 `stage()`。

**输出：** `accepted=false`，原因包含 `not found`。

### 场景二：文件超过大小限制

**配置：** `store.max_artifact_bytes = 4`。

**输入：** 暂存内容 `12345`，共 5 字节。

**输出：** `accepted=false`，原因包含 `max_artifact_bytes`。

### 场景三：版本包含路径穿越

**输入：** `version = ../1`。

**输出：** `accepted=false`，原因包含 `version has illegal char`。

### 覆盖的安全边界

- 文件必须存在。
- 大文件不能无限占用内存和磁盘。
- 版本号不能逃离配置目录。

## 11. `retry_is_idempotent_and_existing_version_cannot_be_replaced`

### 测试目标

同时验证幂等重试和版本不可变性。

### 第一阶段：首次发布

输入 `os2.pkg.demo@2.0`，内容为 `immutable artifact`，期望成功。

### 第二阶段：相同内容重试

使用相同 id、版本和摘要再次发布，期望仍然成功，而且不用覆盖已有文件。

### 第三阶段：不同内容替换

把暂存文件改成 `replacement bytes`，使用新内容的正确摘要再次发布同一 id 和版本。

期望：

- `accepted=false`
- 原因包含 `already exists`

这说明“摘要正确”并不足以覆盖已发布版本。同一个 `id+version` 一旦入库，内容必须保持不变。

## 12. `main()`

```cpp
int main() { return os2::testing::run_all(); }
```

执行四个测试。全部通过返回 `0`，存在失败返回 `1`。

## 13. 测试用例总表

| 测试 | 输入 | 期望输出 |
|---|---|---|
| 正常接收 | 文件存在、摘要一致 | 接受、登记、原子入库 |
| 篡改文件 | 文件内容与摘要不一致 | 拒绝、不登记、不落盘 |
| 文件不存在 | 无暂存文件 | 拒绝 |
| 文件过大 | 5 字节，限制 4 字节 | 拒绝 |
| 危险版本 | `../1` | 拒绝 |
| 相同内容重试 | 同 id、版本、摘要 | 幂等成功 |
| 不同内容替换 | 同 id、版本，不同内容 | 拒绝 |

## 14. 运行方式

```bash
cd /home/haoran/os-module
cmake --build build -j2
ctest --test-dir build -R '^test_artifact_receiver$' --output-on-failure
```

也可以直接运行：

```bash
./build/modules/appstore-portal/test_artifact_receiver
```

## 15. 你的任务边界

这个文件是你负责功能的核心验收测试。修改接收逻辑后，至少保证这里四个测试继续通过。

重点对应源码：

- `FilesystemArtifactVerifier::verify()`
- `safe_component()`
- `normalize_hex()`
- `read_regular_file()`
- `ReceivingStore::make_verifier()`

## 16. 阅读时最应该记住的三点

1. `Fixture` 为每个测试提供独立临时目录并自动清理。
2. 测试通过总线走完整发布链，而不是绕过服务直接调用校验器。
3. 成功、失败、边界和重复提交四类场景共同定义了接收制品的正确行为。

