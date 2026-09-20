# OS² 证书与制品签名管理规则（简单说明 · v0.1 草案）

> **用途：** 说明 OS² 制品供应链签名的最小闭环——**预置管理 → 更新逻辑 → build 签名
> → 商店检查 → 下载运行验证**——的规则、落点与边界。**本阶段=基本 X.509 实现+验证、
> 机器自动执行**；吊销/HSM/在库内验签等**均后放**（见 §7）。
> **状态：** 负责人 2026-07-13 评审通过（"md 即可，我看了没问题"）。
> **实现进度：** ✅ **最小闭环五段全通**——预置(§2)/build 签名(§4)/商店检查(§5)（65bcde8）+
> 下载运行验证(§6，部署边界门，f686871）。缺省关 opt-in；真 openssl 闭环自检
> `make sign-selftest` + `make release-selftest` PASS、28 CTest 绿。**运行验证按范围 A=部署
> 边界门**（宿主/编排侧验签，容器保持零依赖）。容器内 in-service x509 / 进程内验签(mbedTLS)
> 后放（§7）。
> **权威去向：** 登记进受控库《信息安全设计规范》（.docx 双胞经 md2doc）。

---

## 0 范围与原则

- **对象**：制品（模型包 / SDK 包 / os2-pack 产物）的**来源真实性 + 完整性**签名闭环。
- **基元**：X.509 证书 + 非对称签名（ECDSA/RSA）。**适配到既有接缝**（appstore
  `make_verifier()` 扩展点、ArtifactPublish 通道），**非独立造 PKI 产品**。
- **本阶段边界**：只做 **签名 + 证书链 + 有效期** 验证；**机器自动执行**（make 目标/脚本
  链路，无人工密钥仪式）。吊销、在库内验签、命令验签门升级 X.509 等一律**后放**。
- **不碰契约面**：appstore/security `api.hpp`、topics、平台契约**零改动**；签名与证书随
  ArtifactPublish 的 KV 承载（与 sha256/sbom_ref 同通道），不改锁定的 `Artifact` 结构。

---

## 1 信任模型（最小）

```
  根 CA（离线，信任锚）
     └── 签发者证书 signer.crt（发布者/构建身份，持私钥 signer.key）
              └── 对制品摘要签名 → artifact.sig
  信任分发：ca.crt（根证书，公开）随镜像/部署包下发 = 各验证点的信任 bundle
```

- **一级链**（根 CA → 签发者证书）即可满足本阶段；多级中间 CA 后放。
- 验证 = ①`signer.crt` 由 `ca.crt` 签发且在有效期内（证书链+有效期）②`artifact.sig`
  经 `signer.crt` 公钥验签、覆盖制品 sha256 摘要。二者全过才放行。

---

## 2 预置管理（provisioning）

- **密钥/证书位置**：`deploy/certs/`
  - `ca.key` / `ca.crt`：根 CA（`ca.crt` 为信任锚，随部署包分发）。
  - `signer.key` / `signer.crt`：签发者（构建侧持有 `signer.key`）。
- **生成**：`make certs`（→ `tools/gen_certs.sh`，openssl 自动生成，可复现）。
- **铁律**：**私钥（`*.key`）永不入库**——`deploy/certs/*.key` 入 `.gitignore`；
  `ca.crt`/`signer.crt`（公开证书）可入库或随镜像。演示 PKI 由 `make certs` 现场生成。
- **有效期**：演示证书默认有效期（如 `ca` 3650 天 / `signer` 825 天，见脚本参数）。

---

## 3 更新逻辑（rotation，最小）

- **轮换**：重跑 `make certs` 重新签发 `signer.crt`（沿用或更新 `ca`）→ 重新分发
  `ca.crt` 信任 bundle → 重新 `make sign-artifact`。本阶段=**重生成+重分发**，
  不做在线续期/自动轮换（后放）。
- **失效应对**：证书过期 → 验证点按"有效期"判失败拒绝 → 走轮换重签。
- **CA 更换**：更新 `ca.crt` 分发即切换信任锚（旧签名随即失效，须重签）。

---

## 4 build 签名（sign）

- **动作**：构建/打包末尾对制品**摘要签名**。
  - `make sign-artifact ARTIFACT=<file>`（→ `tools/sign_artifact.sh`）：
    `sha256(制品)` → `openssl dgst -sha256 -sign signer.key` → 产出 `<file>.sig`；
    连同 `signer.crt` 一并纳入发布材料。
- **机器自动执行**：签名是打包流水线的一步（无人工介入）；后续并入 os2-pack 时，
  `.sig` + `signer.crt` 成为 pack 清单项（**签名件=pack 产物**，对齐 ROADMAP KPI 口径）。

---

## 5 商店检查（store admission）

- **落点**：`modules/appstore-portal` 的 `make_verifier()` 扩展点 → 规划新增
  `impl/signature_verifier.hpp` `SignatureVerifier : IArtifactVerifier`（替换/叠加
  现 `DigestVerifier`）。
- **动作**：`ArtifactPublish` 到达时，除现有 sha256 非空校验外，追加：
  ①证书链+有效期：`ca.crt` 验 `signer.crt`；②签名：`signer.crt` 公钥验 `artifact.sig`
  覆盖 `sha256`。**任一不过 → 拒绝入库**（`accepted=false`，reason 落审计）。
- **签名/证书承载**：随 `ArtifactPublish` 的 KV（`sig` / `signer_cert`，与 sha256/sbom_ref
  同通道），**不改 `Artifact` 契约结构**。
- **本阶段验签实现**：机器自动执行 = 服务侧调用 openssl 完成链+签名验证（最小闭环、
  无需引入进程内密码学库）；**进程内 libcrypto/mbedTLS 验签后放**（§7）。

---

## 6 下载运行验证（download → run）

- **落点**：部署/节点拉起前（deploy 侧 / 节点 bootstrap）对下载到本地的制品**再验一次**
  （链+有效期+签名），**验签通过才运行**；失败则拒绝拉起并出证据事件。
- **原则**：入库验一次不够——**下载/运行点独立复验**（信任不随传输默认延续）。
- **机器自动执行**：验证是拉起流程的一步，失败即阻断，无人工放行。

---

## 最小闭环时序

```
 构建侧                     商店(appstore)              部署/运行侧
   │  make sign-artifact        │                          │
   │  sha256+sign → .sig        │                          │
   ├── ArtifactPublish(sig,cert)►│                          │
   │                            │ 链+有效期+签名验证        │
   │                            │  ✗→拒绝入库(审计)         │
   │                            │  ✓→登记                  │
   │                            ├── 下载(制品+.sig+cert) ──►│
   │                            │                          │ 运行前复验(链+签名)
   │                            │                          │  ✗→拒绝拉起(证据)
   │                            │                          │  ✓→运行
```

---

## 7 后放项（本阶段不做，登记待排期）

| 项 | 归属 |
|---|---|
| 证书**吊销**（CRL / OCSP） | M3 |
| **进程内验签**（mbedTLS，去 openssl CLI 依赖=容器零依赖破除） | **1.5期**（选项 B 真密码库绑定；OS2_WITH_MBEDTLS 切换点已留 platform/x509.hpp） |
| ~~**命令验签门**升级 X.509~~ | ✅ **一期已做逻辑（选项 B，2026-07-17，负责人核准）**：X509GateEngine 命令门 X.509 档（证书链+有效期+kid↔CN 绑定+可插拔后端），`security.command_auth=x509` 切换、缺省 hmac 零变化；数学本体经 SpawnOpenssl 后端（一期真件），进程内 mbedTLS=1.5期。方案=`X509_INSERVICE_PLAN.md` |
| 多级中间 CA / HSM / 密钥托管 / 在线续期轮换 | M3+/二期 |
| ~~os2-pack 制品（SBOM + 签名清单）~~ ✅ 已建（a651a39，签名件=pack 产物）；深度依赖图 SBOM 后放 | M2.3 ✅ |

---

## 8 实现落点小结（规划，代码未落）

| 环节 | 落点 | 状态 |
|---|---|---|
| 预置/生成 | `make certs` → `tools/gen_certs.sh`；`deploy/certs/`（`*.key` gitignore） | ✅ 65bcde8 |
| build 签名 | `tools/sign_artifact.sh`（openssl dgst -sign）；`make sign-selftest` 自检 | ✅ 65bcde8 |
| 商店检查 | `appstore-portal` `make_verifier()` → `impl/signature_verifier.hpp`（组合校验，opt-in） | ✅ 65bcde8 |
| 运行验证 | 部署边界门：`tools/verify_release.sh` / `make release-verify`（宿主/编排侧，容器零依赖） | ✅ f686871 |
| 配置 | `security.sig_algo`（hmac 缺省/ x509 启用）、`store.sign_dir`/`store.ca_bundle`、`store.verify_script` | ✅ 键已接 |

> **运行期 openssl 取舍（§6，负责人 2026-07-13 定范围 A）：** 运行期镜像 `debian:bookworm-slim`
> 明写"零第三方运行时依赖"，不带 openssl CLI。**采用部署边界门**——"下载运行验证"在具 openssl 的
> 部署编排/宿主侧执行（`verify_release.sh`：拉起/分发前复验，不过即阻断），**容器保持零依赖**、
> 默认演示不受影响。容器内 in-service x509（需给镜像装 openssl）与进程内验签（mbedTLS）为后放项。

> **边界重申**：security-mgr/appstore `api.hpp`、topics、平台契约零改动；缺省不启用
> （`sig_algo=hmac` 存量行为不变），`x509` 为 opt-in。实现前须负责人核准（高敏 §31）。
