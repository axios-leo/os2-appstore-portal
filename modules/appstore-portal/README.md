# 应用商店与门户 appstore-portal

- **Owner（人类审批）：** `@os2/owner-store`
- **定位：** 支撑软件工厂更新、灰度回滚、可视化操作与证据导出；把 OS 状态转为可操作界面。
- **契约面：** ArtifactPublish / ActivationCommand；制品记录、回滚点。
- **M0.5 状态：** 框架类就位（`src/store_service.hpp`，契约主题已接线，桩可运行、单测通过）。
- **可授权 AI 的任务：** 制品发布流水线、灰度策略、前端组件、可视化、单测。
- **规约源：** 受控库《架构说明》§8.8、制品仓/应用商店口径。

## M0.5 框架类（架构师提供，勿改）

- **框架类：** `StoreService`（`src/`）+ 契约面 `include/os2/appstore_portal/api.hpp`
- **你的扩展点：** `make_verifier / on_activated` —— 实现写在 `src/impl/`，配单测
- **M1 方向：** 发布流水线、灰度策略、门户界面
- **必读：** `docs/DEVELOPMENT_GUIDE.md` · `docs/MODULE_BOUNDARIES.md`

## 制品接收实现（本模块扩展层）

`src/impl/artifact_receiver.hpp` 提供 `ReceivingStore`。发布方先将真实制品放入：

```text
<store.incoming_dir>/<artifact_id>-<version>.artifact
```

随后发送既有 `ArtifactPublish` 请求。接收器依次执行既有格式/签名校验、真实文件
SHA-256 复算、大小限制、同版本不可变检查，并原子写入：

```text
<store.repository_dir>/<artifact_id>/<version>/artifact.bin
```

配置项：

- `store.incoming_dir`：受控暂存目录，必须配置；
- `store.repository_dir`：端侧制品仓目录，必须配置；
- `store.max_artifact_bytes`：单制品字节上限，缺省 256 MiB；
- `store.gc_orphans_on_start`：启动时删除崩溃残留临时文件和无索引制品，缺省 `false`。

同一 `artifact_id+version+sha256` 重试为幂等成功；暂存文件缺失、摘要不一致、超限、
路径分量非法或仓内同版本内容不同均拒绝登记。当前公共契约尚未定义传输 URI/介质回执，
所以本阶段使用暂存目录约定；正式跨节点传输仍需统一契约和集成负责人确认。

接收过程使用目标版本目录内的随机独占临时文件，按 64 KiB 分块复制并同步计算
SHA-256；校验通过后以“不覆盖”语义提交。同版本目标已存在时只允许摘要相同的幂等
重试。配置状态索引后，服务启动会逐项核对仓库文件存在性、常规文件类型和摘要；索引
损坏、文件缺失或摘要不一致均拒绝启动。未开启 GC 时，孤儿文件和临时文件只记录告警。
