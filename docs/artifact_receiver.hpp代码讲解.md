# `artifact_receiver.hpp` 代码讲解

源码：`modules/appstore-portal/src/impl/artifact_receiver.hpp`

## 1. 文件的总体职责

这个文件实现“接收真实制品文件”功能，同时支持同节点暂存文件和跨节点分块上传。

同节点兼容流程约定上游先把文件放到暂存目录：

```text
<store.incoming_dir>/<artifact_id>-<version>.artifact
```

跨节点流程则通过 `ArtifactUploadPrepare`、`ArtifactUploadChunk`、
`ArtifactUploadCommit`（以及可选的 `ArtifactUploadAbort`）传输文件，不要求共享目录。

收到发布或上传请求后，本文件负责：

1. 先执行已有的 id、摘要格式和签名校验。
2. 检查暂存目录和仓库目录是否已配置。
3. 检查版本号能否安全用于路径。
4. 读取真实暂存文件并限制大小。
5. 重新计算真实 SHA-256。
6. 防止同一 id 和版本被不同内容替换。
7. 使用目标目录中的独占临时文件和 `link(2)` 不覆盖提交写入仓库。
8. 相同内容重试时返回幂等成功。
9. 清理中断或超时的上传会话。
10. 启动时核对持久化索引与仓库文件，可按配置回收孤儿和临时文件。

> D2 说明：仓库中的 `(artifact_id, version)` 同时约束文件内容和关键元数据；同版本
> 只有完全相同的重试才按幂等成功处理。

入库路径是：

```text
<store.repository_dir>/<artifact_id>/<version>/artifact.bin
```

## 2. 在发布链中的位置

```text
ArtifactPublish
    ↓
StoreService::handle_publish()
    ↓
FilesystemArtifactVerifier::verify()
    ↓ 先调用 inner_
格式校验 / 可选签名校验
    ↓
真实文件读取和 SHA-256 复核
    ↓
原子写入仓库
    ↓ 返回 true
StoreService 登记 Artifact 元数据
```

文件接收被实现成“校验器”，因此不用改动 `StoreService` 的公共发布流程。

## 3. 依赖

| 头文件 | 用途 |
|---|---|
| `<array>` | 64 KiB 读取缓冲区 |
| `<cctype>` | 检查字符、转换摘要大小写 |
| `<filesystem>` | 安全拼接和检查路径 |
| `<fstream>` | 二进制读取制品文件 |
| `<memory>` | `unique_ptr` 校验器组合 |
| `<string>` | 文件内容、路径配置、失败原因 |
| `grayscale_store.hpp` | `GrayscaleStore` 和上游校验链 |
| `atomic_file.hpp` | 原子写入仓库文件 |
| `hash.hpp` | 计算 SHA-256 |

## 4. `FilesystemArtifactVerifier` 类

```cpp
class FilesystemArtifactVerifier final : public IArtifactVerifier
```

### 4.1 类的作用

它包装另一个 `IArtifactVerifier`：

```text
inner_ 校验元数据和签名
    ↓ 成功
FilesystemArtifactVerifier 校验真实文件并入库
```

`final` 表示不允许继续继承这个类。

### 4.2 构造函数

```cpp
FilesystemArtifactVerifier(
    std::unique_ptr<IArtifactVerifier> inner,
    std::string incoming_dir,
    std::string repository_dir,
    std::uint64_t max_artifact_bytes)
```

**访问权限：** `public`。

**调用者：** `ReceivingStore::make_verifier()`。

**输入：**

| 参数 | 含义 |
|---|---|
| `inner` | 内层格式、摘要和签名校验器 |
| `incoming_dir` | 暂存目录 |
| `repository_dir` | 正式仓库目录 |
| `max_artifact_bytes` | 允许读取的最大字节数 |

**输出：** 构造函数没有返回值，生成一个文件系统校验器对象。

**内部行为：** 使用 `std::move` 把校验器和两个目录字符串保存为成员。

**所有权：** `inner_` 是 `unique_ptr`，由本对象独占并自动释放。

### 4.3 `verify()`

```cpp
bool verify(const Artifact& artifact, std::string& reason) override
```

**访问权限：** `public`。

**调用者：** `StoreService::handle_publish()`。

**输入：**

| 参数 | 类型 | 含义 |
|---|---|---|
| `artifact` | `const Artifact&` | 发布请求组装出的制品元数据 |
| `reason` | `std::string&` | 失败原因输出参数 |

**输出：**

- `true`：校验和入库成功，或者相同制品已存在。
- `false`：任一安全检查或文件操作失败。

**完整执行步骤：**

1. 检查 `inner_` 存在并调用内层校验器。
2. 检查暂存目录和仓库目录非空。
3. 使用 `safe_component()` 检查版本号。
4. 计算源路径和目标路径。
5. 使用 `read_regular_file()` 读取暂存文件。
6. 计算真实内容 SHA-256，并与请求摘要比较。
7. 检查目标版本是否已经存在。
8. 已存在且摘要相同：幂等成功，不重写。
9. 已存在但摘要不同：拒绝覆盖。
10. 不存在时创建父目录。
11. 使用 `atomic_write()` 原子写入 `artifact.bin`。

### 4.4 源路径和目标路径

源路径：

```cpp
incoming_dir / (artifact_id + "-" + version + ".artifact")
```

目标路径：

```cpp
repository_dir / artifact_id / version / "artifact.bin"
```

示例：

```text
incoming/os2.pkg.demo-1.0.0.artifact
repository/os2.pkg.demo/1.0.0/artifact.bin
```

### 4.5 `verify()` 失败输出

| 条件 | `reason` |
|---|---|
| 内层校验失败 | 内层校验器给出的原因 |
| 目录未配置 | `artifact receiver directories are not configured` |
| 版本字符非法 | `version has illegal char (allowed: alnum . _ -)` |
| 暂存文件不存在 | `artifact staging file not found` |
| 路径不是普通文件 | `artifact staging path must be a regular file` |
| 文件打不开 | `cannot open artifact staging file` |
| 文件过大 | `artifact exceeds store.max_artifact_bytes` |
| 文件读取不完整 | `cannot read complete artifact staging file` |
| 真实摘要不匹配 | `artifact content sha256 mismatch` |
| 已有版本内容不同 | `artifact version already exists with different content` |
| 无法创建仓库目录 | `cannot create artifact repository directory` |
| 原子写入失败 | `cannot persist artifact into repository` |

### 4.6 `verify()` 的状态变化

成功且目标不存在时，会在仓库中新增：

```text
<repository>/<id>/<version>/artifact.bin
```

失败时不会返回成功，因此 `StoreService` 不会登记元数据。

## 5. `safe_component()`

```cpp
static bool safe_component(const std::string& value)
```

**访问权限：** `private static`。

**调用者：** `verify()`。

**输入：** 要作为单个路径组成部分的版本字符串。

**输出：**

- `true`：可以安全作为目录名。
- `false`：不安全。

**拒绝条件：**

- 空字符串。
- 长度超过 64。
- 值为 `.` 或 `..`。
- 含有字母、数字、点、下划线、连字符之外的字符。

它会拒绝 `/`、`\`、空格、引号、分号等字符，从而阻止路径穿越和命令字符进入路径。

**状态变化：** 无。

## 6. `normalize_hex()`

```cpp
static std::string normalize_hex(std::string value)
```

**输入：** 一份十六进制字符串副本。

**输出：** 全部转换为小写的新字符串。

**用途：** 让 `ABCDEF` 和 `abcdef` 被视为相同摘要。

**状态变化：** 只修改局部副本，不修改原始 `Artifact`。

## 7. `read_regular_file()`

```cpp
bool read_regular_file(
    const std::filesystem::path& path,
    std::string& content,
    std::string& reason) const
```

**调用者：** `verify()`，既读取暂存文件，也读取已存在的仓库文件。

**输入与输出参数：**

| 参数 | 方向 | 含义 |
|---|---|---|
| `path` | 输入 | 要读取的路径 |
| `content` | 输出 | 成功时保存完整文件字节 |
| `reason` | 输出 | 失败时保存原因 |

**返回值：** 成功返回 `true`，失败返回 `false`。

**执行步骤：**

1. 使用 `symlink_status()` 获取路径状态。
2. 路径不存在时拒绝。
3. 符号链接或非普通文件时拒绝。
4. 以二进制模式打开。
5. 清空旧的 `content`。
6. 每次最多读取 64 KiB。
7. 每批追加前检查总大小是否超过限制。
8. 循环结束后确认是正常 EOF。

**安全意义：**

- 拒绝符号链接，降低通过链接越界读取其他文件的风险。
- 限制最大字节数，避免无限占用内存。
- 二进制模式保证内容字节不被文本转换。

**实现特点：** 当前会把整个制品读入 `std::string`。默认上限为 256 MiB，因此内存占用可能接近制品大小。

## 8. 成员变量

| 成员 | 类型 | 作用 |
|---|---|---|
| `inner_` | `unique_ptr<IArtifactVerifier>` | 上游格式和签名校验链 |
| `incoming_dir_` | `string` | 暂存目录 |
| `repository_dir_` | `string` | 正式仓库目录 |
| `max_artifact_bytes_` | `uint64_t` | 最大允许文件大小 |

## 9. `ReceivingStore` 类

```cpp
class ReceivingStore final : public GrayscaleStore
```

### 9.1 类的作用

它是最终可运行的接收制品商店，把文件系统校验器接到 `GrayscaleStore` 的校验链外层。

`final` 表示不允许继续继承。

### 9.2 继承构造函数

```cpp
using GrayscaleStore::GrayscaleStore;
```

这不是普通变量声明，而是让 `ReceivingStore` 直接复用父类构造函数。

因此可以继续使用：

```cpp
ReceivingStore{ServiceIdentity{...}, ServiceContext{...}}
```

### 9.3 `make_verifier()`

```cpp
std::unique_ptr<IArtifactVerifier> make_verifier() override
```

**调用者：** `StoreService::on_init()` 通过虚函数调用。

**输入：** 无显式参数，通过 `config()` 读取配置。

**输出：** 一个 `FilesystemArtifactVerifier`，其静态类型是 `unique_ptr<IArtifactVerifier>`。

**配置：**

| 配置项 | 作用 | 默认值 |
|---|---|---|
| `store.incoming_dir` | 暂存目录 | 空，空会拒绝发布 |
| `store.repository_dir` | 仓库目录 | 空，空会拒绝发布 |
| `store.max_artifact_bytes` | 最大制品字节数 | 256 MiB |

**内部校验器：** `GrayscaleStore::make_verifier()` 返回摘要格式及可选签名校验链。

最终组合：

```text
FilesystemArtifactVerifier
    └─ SignatureArtifactVerifier（配置 x509 时）
         └─ Sha256FormatVerifier
```

## 10. `atomic_write()` 的作用

入库不直接打开目标文件覆盖，而是：

```text
写 destination.tmp
    ↓
fsync 文件数据
    ↓
rename 临时文件到正式文件
    ↓
尽力 fsync 父目录
```

进程崩溃或断电时，读者看到旧完整文件或新完整文件，不会看到半个文件。

## 11. 幂等与不可变性

| 情况 | 结果 |
|---|---|
| 目标不存在 | 创建目录并原子入库 |
| 目标存在且摘要相同 | 返回成功，不重复写 |
| 目标存在且摘要不同 | 返回失败，禁止替换 |

因此相同请求可以安全重试，但已发布版本不能偷偷换内容。

## 12. 函数总表

| 类 | 函数 | 输入 | 输出 | 作用 |
|---|---|---|---|---|
| `FilesystemArtifactVerifier` | 构造函数 | 内层校验器、目录、大小 | 对象 | 保存配置和所有权 |
| `FilesystemArtifactVerifier` | `verify()` | `Artifact`、原因引用 | `bool` | 校验并入库 |
| `FilesystemArtifactVerifier` | `safe_component()` | 路径组成部分 | `bool` | 阻止危险版本路径 |
| `FilesystemArtifactVerifier` | `normalize_hex()` | 摘要字符串 | 小写摘要 | 大小写无关比较 |
| `FilesystemArtifactVerifier` | `read_regular_file()` | 路径 | 内容、原因、`bool` | 安全限量读取文件 |
| `ReceivingStore` | 继承构造函数 | 身份、上下文 | 对象 | 复用父类构造 |
| `ReceivingStore` | `make_verifier()` | 配置 | 校验器指针 | 组装最终接收链 |

## 13. 你的任务边界

这是三个 `impl` 文件中与你最直接相关的文件。你主要负责：

- 接收路径约定。
- 文件类型和大小检查。
- 真实摘要复核。
- 幂等接收。
- 已发布版本不可替换。
- 安全、原子入库。
- 对应测试。

## 14. 阅读时最应该记住的三点

1. 文件先由上游放入暂存目录，发布消息不直接携带文件。
2. `verify()` 返回成功后，`StoreService` 才登记元数据。
3. 相同版本相同内容可以重试，不同内容绝不允许覆盖。
