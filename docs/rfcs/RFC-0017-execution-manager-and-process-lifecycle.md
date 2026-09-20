# RFC-0017：执行管理程序（EM）与服务进程生命周期（契约面 minor）

| 项 | 内容 |
|---|---|
| 状态 | **提案 → 实施中**（契约 `1.16.0` → `1.17.0`）。 |
| 触发 | 负责人 2026-08-14 给的运行形态：「各域启动，做一个单独的**执行管理程序（EM）**用于启动 manifest 中的进程（即运行服务实例的程序），目前每个域就放一个；展演台中 EM 启动作为**启动中**，进程启动后直接**域状态变绿**」，以及框架侧「主程序中**上报进程状态**、启动服务、**服务与 OS 管理总线接口**（如启动服务、服务状态上报、中止服务等）」。 |
| 影响面 | `contracts/topics/topics.yaml` +2 主题、`data_dictionary` +2 messages 段、`SURFACE.lock` 重刷；新模块 `modules/compute-hosting/`；新二进制 `os2_em`；`os2-gen` 生成的服务框架 +两段；展演台域状态口径。 |
| 不做 | 不做容器编排（负责人定的形态是**进程**，不是 Docker——`DEMO2_PLAN` 图上 `Docker*n` 随之简化）；不做镜像仓、滚动升级、亲和性调度；EM **不解释业务**，只管进程的起停与存活。 |

---

## 1 为什么需要它

现在的服务进程是"自己跑起来、跑到 `OS2_RUN_SECONDS` 就退"——**没有任何人负责把它拉起来，
也没有通道让 OS 让它停**。展演台上域的绿点来自节点自身的 `ResourceReport`，
表达的是"这台机上的 os2_node 活着"，**不是"这台机上该跑的服务都跑起来了"**。
这两件事在单机 compose 里恰好同时发生，所以差别没暴露；换成真机、服务由各开发单元
自己编译出来的独立进程之后，差别就是演示的主要内容。

EM 补的就是这一层：**部署清单 → 进程 → 状态**。

## 2 主题（两个，不多加）

### 2.1 `ProcessReport`（pub · `os2.mgmt.exec.process`）

EM 与服务进程共同上报。EM 报"我计划拉起哪些、现在各是什么状态"，服务进程自报"我起来了"。

| 键 | 型 | 说明 |
|---|---|---|
| `node_id` | string | 所在节点 |
| `instance_id` | string | 运行实例标识（与 `ServiceRegister` 同一个，**不另造标识**） |
| `service_id` | string | 逻辑服务标识 |
| `state` | enum | `planned`｜`starting`｜`running`｜`stopping`｜`exited`｜`failed` |
| `pid` | string | 进程号；未起时为空 |
| `exit_code` | string | 退出码；仅 `exited`/`failed` 有值 |
| `reporter` | enum | `em`｜`service`——**谁说的要能分清**：EM 说"我把它拉起来了"和进程自己说"我起来了"是两件事，前者只证明 fork 成功 |
| `manifest` | string | 部署清单实体 id；EM 报时必填 |
| `ts` | string | 毫秒时戳 |

### 2.2 `ProcessControl`（reqrep · `os2.mgmt.exec.control`）

| 方向 | 键 | 说明 |
|---|---|---|
| req | `node_id` / `instance_id` / `action` | `action` ∈ `start`｜`stop`｜`restart` |
| rep | `result` / `reason` / `reason_code` | 稳定错误码；成功 `OS2-0000` |

**服务进程侧也订阅它**：收到针对自己 `instance_id` 的 `stop` 即优雅退出
（先注销/停心跳，再退），这就是负责人说的"服务与 OS 管理总线接口（启动服务、中止服务）"。
"启动服务"由 EM 负责（进程还没起，进程自己收不到消息——这一点要说清，否则会设计成
一个永远收不到的接口）。

> **为什么不复用 `ActivationCommand`**：那是应用商店的**版本激活/灰度回滚**，
> 语义是"哪个版本可用"，不是"这个进程起没起"。挤进去会让两件事共享一个错误码空间，
> 排障时分不清"没激活"和"起不来"。

## 3 状态机（有意做浅）

```
planned ──EM fork──> starting ──进程自报──> running
   ▲                    │                     │
   │                    └── fork 失败 ──> failed
   └── stop 完成 <── stopping <── ProcessControl(stop)
                          │
                          └── 进程退出 ──> exited
```

**只有一处判断值得强调**：`starting → running` **必须由进程自己报**，不能由 EM 代报。
EM 只知道 fork 成功，不知道进程有没有初始化好总线、有没有注册进服务目录。
让 EM 代报就是在证据链上撒谎——这正是 device 命令面那次"代偿零效果"的同类错误。

## 4 展演台域状态口径

| 域状态 | 判据 |
|---|---|
| 灰（未启动） | 没收到该节点的 `ProcessReport` |
| **黄（启动中）** | EM 已上报，但清单内实例**未全部** `running` |
| **绿（就绪）** | 清单内实例**全部** `running`（且节点自身 `ResourceReport` 新鲜） |
| 红（故障） | 有实例处于 `failed`，或曾 `running` 的实例变成 `exited` |

——**状态来自真实上报，不是页面定时器**。这条是 2026-07-21「demo 去表演化」定下的口径，
本次沿用：黄不是"演一下启动过程"，是真的还没起齐。

## 5 判据

| # | 判据 | 怎么验 |
|---|---|---|
| 1 | EM 按清单拉起进程并逐个上报 | 单测：假 spawner，清单 3 项 ⇒ 3 条 `planned`→`starting` |
| 2 | `running` 只能由 `reporter=service` 置位 | 单测：EM 报 `running` 被拒/降级为 `starting`（判负） |
| 3 | `stop` 令进程优雅退出 | 单测：控制面下发 stop ⇒ `stopping`→`exited`，退出码 0 |
| 4 | fork 失败进 `failed` 且带 `exit_code` | 单测：假 spawner 返回失败 |
| 5 | 域状态三档由真实上报推导 | 页面门：`showcase_boot.test.mjs` 断言判据表与实现一致 |
| 6 | 契约面锁随 bump 重刷 | `make contracts-freeze` + 十一段门禁 |

## 6 更新记录

| 日期 | 变更 |
|---|---|
| 2026-08-14 | 起草。触发＝负责人给的 EM 运行形态与框架侧接口清单。 |
