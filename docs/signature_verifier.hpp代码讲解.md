# `signature_verifier.hpp` 代码讲解

源码：`modules/appstore-portal/src/impl/signature_verifier.hpp`

## 1. 文件的总体职责

这个文件实现制品的可选 X.509 签名验证。

当配置：

```text
security.sig_algo=x509
```

应用商店会在格式校验之后继续检查：

1. 签发者证书是否由可信 CA 签发。
2. 签发者证书是否在有效期内。
3. `.sig` 是否确实是对制品摘要的有效签名。

未启用 X.509 时，只执行内层格式和摘要校验，保持原有行为。

## 2. 文件和签名材料约定

按制品 id 定位签名文件：

```text
<sign_dir>/<artifact_id>.sig
<sign_dir>/signer.crt
<sign_dir>/ca.crt
```

也可以通过配置提供单独的 CA bundle。

验证脚本默认是：

```text
tools/verify_artifact.sh
```

## 3. 调用关系

```text
GrayscaleStore::make_verifier()
    ↓
SignatureArtifactVerifier
    ├─ inner_->verify()
    │    └─ Sha256FormatVerifier
    ↓ 启用 x509 时
ISignatureCheck::check()
    ↓ 生产实现
OpensslSignatureCheck::check()
    ↓
x509::spawn_verify_script()
    ↓ argv 直传
tools/verify_artifact.sh
    ↓
openssl verify + openssl dgst
```

## 4. 为什么使用两层接口

签名决策和具体 OpenSSL 执行被分开：

- `SignatureArtifactVerifier` 决定先做什么、是否启用签名、失败如何传递。
- `ISignatureCheck` 定义后端接口。
- `OpensslSignatureCheck` 是生产后端。
- 测试可以注入 `FakeSig`，无需真实证书和 OpenSSL 环境。

## 5. `ISignatureCheck` 类

```cpp
class ISignatureCheck
```

这是签名后端接口。

### 5.1 虚析构函数

```cpp
virtual ~ISignatureCheck() = default;
```

**输入/输出：** 无。

**作用：** 允许通过 `ISignatureCheck*` 或智能指针安全销毁派生后端。

### 5.2 `check()`

```cpp
virtual bool check(
    const std::string& artifact_id,
    const std::string& sha256,
    std::string& reason) = 0;
```

**输入：**

| 参数 | 含义 |
|---|---|
| `artifact_id` | 用于定位 `<id>.sig` |
| `sha256` | 需要验证签名的摘要文本 |
| `reason` | 失败原因输出参数 |

**输出：** 证书链和签名全部通过返回 `true`，否则返回 `false`。

`= 0` 表示纯虚函数，所以 `ISignatureCheck` 不能直接实例化。

## 6. `OpensslSignatureCheck` 类

```cpp
class OpensslSignatureCheck : public ISignatureCheck
```

它通过外部脚本和 OpenSSL CLI 完成生产验签。

### 6.1 构造函数

```cpp
OpensslSignatureCheck(
    std::string sign_dir,
    std::string ca_bundle,
    std::string script)
```

**输入：**

| 参数 | 含义 |
|---|---|
| `sign_dir` | `.sig`、`signer.crt` 和默认 `ca.crt` 所在目录 |
| `ca_bundle` | 自定义 CA 文件；可为空 |
| `script` | 验签脚本路径 |

**输出：** 构造一个后端对象。

**内部行为：** 使用 `std::move` 保存三个配置字符串。

### 6.2 `check()`

```cpp
bool check(const std::string& id,
           const std::string& sha256,
           std::string& reason) override
```

**调用者：** `SignatureArtifactVerifier::verify()`。

**输入：** 制品 id、摘要和失败原因输出引用。

**输出：**

- `true`：外部验签脚本退出码为 0。
- `false`：进程启动失败或脚本返回非 0。

**路径计算：**

```text
sig  = sign_dir/id.sig
cert = sign_dir/signer.crt
ca   = ca_bundle 非空 ? ca_bundle : sign_dir/ca.crt
```

**外部调用：**

```cpp
x509::spawn_verify_script(script_, sha256, sig, cert, ca)
```

参数以 argv 数组直接传递，不拼接 shell 命令字符串。

**返回码处理：**

| `rc` | 输出 | 原因 |
|---:|---|---|
| `0` | `true` | 验签成功 |
| `-1` | `false` | `x509 verify spawn failed for <id>` |
| 其他非 0 | `false` | `x509 signature/chain verify failed for <id>` |

### 6.3 成员变量

| 成员 | 作用 |
|---|---|
| `sign_dir_` | 签名材料目录 |
| `ca_` | 自定义 CA 路径 |
| `script_` | 验签脚本路径 |

## 7. `SignatureArtifactVerifier` 类

```cpp
class SignatureArtifactVerifier : public IArtifactVerifier
```

### 7.1 类的作用

它是组合校验器：先调用内层格式校验，再根据开关决定是否调用签名后端。

### 7.2 构造函数

```cpp
SignatureArtifactVerifier(
    std::unique_ptr<IArtifactVerifier> inner,
    std::unique_ptr<ISignatureCheck> sig,
    bool enabled)
```

**输入：**

| 参数 | 含义 |
|---|---|
| `inner` | 内层制品校验器 |
| `sig` | 签名后端 |
| `enabled` | 是否实际执行签名验证 |

**输出：** 构造组合校验器对象。

**所有权：** 两个 `unique_ptr` 都转移给本对象并自动释放。

**前提：** 正常构造时 `inner` 和启用状态下的 `sig` 必须非空；当前代码不做空指针保护。

### 7.3 `verify()`

```cpp
bool verify(const Artifact& a, std::string& reason) override
```

**调用者：** `StoreService::handle_publish()`，也可能被外层 `FilesystemArtifactVerifier` 调用。

**输入：** 制品只读引用和失败原因输出引用。

**输出：** 所需校验全部通过返回 `true`，任一步失败返回 `false`。

**执行步骤：**

```text
inner_->verify(a, reason)
    ├─ false → 立即返回 false，不调用签名后端
    └─ true
         ↓
enabled_ == false
    → 返回 true

enabled_ == true
    → sig_->check(id, sha256, reason)
    → 返回后端结果
```

**短路意义：** 格式都不合法的制品不会进入昂贵的证书和签名验证。

## 8. `verify_artifact.sh` 的输入输出

脚本接收四个位置参数：

```text
1. sha256 文本
2. .sig 文件
3. signer.crt
4. ca.crt
```

### 第一步：证书链和有效期

```bash
openssl verify -CAfile "$CA" "$CERT"
```

失败退出码为 2。

### 第二步：提取公钥并验证签名

```bash
openssl x509 -pubkey -noout -in "$CERT"
printf '%s' "$DIGEST" | openssl dgst -sha256 -verify ...
```

失败退出码为 3。

参数个数错误退出 64，全部成功退出 0。

## 9. 为什么不用 shell 字符串拼接

旧式危险做法类似：

```text
"script " + artifact_id + " ..."
```

如果 id 中包含引号、分号或 `$()`，可能被 shell 当成新命令。

当前实现使用 `posix_spawn` 风格的 argv 直传。每个值只是一个位置参数，即使包含 shell 元字符也不会被解释执行。

上游 id 字符白名单仍保留，形成双重防护。

## 10. 三种运行结果

| 内层格式 | `enabled` | 签名后端 | 最终结果 |
|---|---:|---|---|
| 失败 | 任意 | 不调用 | 失败 |
| 成功 | `false` | 不调用 | 成功 |
| 成功 | `true` | 成功 | 成功 |
| 成功 | `true` | 失败 | 失败 |

## 11. 成员变量

### `OpensslSignatureCheck`

| 成员 | 作用 |
|---|---|
| `sign_dir_` | 签名材料目录 |
| `ca_` | CA bundle |
| `script_` | 验签脚本 |

### `SignatureArtifactVerifier`

| 成员 | 作用 |
|---|---|
| `inner_` | 内层格式/摘要校验器 |
| `sig_` | 签名后端 |
| `enabled_` | 签名开关 |

## 12. 函数总表

| 类 | 函数 | 输入 | 输出 | 作用 |
|---|---|---|---|---|
| `ISignatureCheck` | 析构函数 | 无 | 无 | 安全销毁派生后端 |
| `ISignatureCheck` | `check()` | id、摘要、原因 | `bool` | 定义验签接口 |
| `OpensslSignatureCheck` | 构造函数 | 目录、CA、脚本 | 对象 | 保存生产配置 |
| `OpensslSignatureCheck` | `check()` | id、摘要、原因 | `bool` | 启动脚本验签 |
| `SignatureArtifactVerifier` | 构造函数 | 内层、后端、开关 | 对象 | 组合校验器 |
| `SignatureArtifactVerifier` | `verify()` | 制品、原因 | `bool` | 格式后追加签名检查 |

## 13. 与另外两个 impl 文件的关系

```text
grayscale_store.hpp
    创建 SignatureArtifactVerifier
        ↓
signature_verifier.hpp
    完成可选 X.509 检查
        ↓ 被包装
artifact_receiver.hpp
    再检查真实文件并入库
```

最终顺序是：

```text
格式 → 签名 → 真实文件摘要 → 原子入库
```

## 14. 你的任务边界

签名后端不是你当前接收制品任务的主要实现，但接收制品必须保留这条校验链，不能绕过签名直接入库。

联调时需要确认：

- 签名目录由谁装配。
- 签名文件命名是否与 `artifact_id` 一致。
- `signer.crt` 和 CA 是否正确部署。
- 运行镜像是否包含 OpenSSL 和验证脚本。

## 15. 阅读时最应该记住的三点

1. 先过格式校验，再决定是否执行签名检查。
2. X.509 是配置启用项，未启用时保持原流程。
3. 外部脚本使用 argv 直传，避免 shell 命令注入。
