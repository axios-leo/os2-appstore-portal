# RFC-0006：建模二分落地——资源并入节点 + 关联关系机器校验（契约 minor）

| 项 | 内容 |
|---|---|
| 状态 | **✅ 已实施落地（契约 v1.6.0，2026-07-21）**。负责人 2026-07-21 三条批复：①`resource` 模型**直接删除**（非停用留痕）②契约 **bump**、发现的问题直接改掉 ③设计态三列改造**不合并到 M6**（原则：界面要体现成熟度）。九段门禁全绿 + 33 CTest 全绿 + 分布式台架 7/7。 |
| 触发 | **0720 边界会（吕总主持）决议**：①建模二分——A 资源侧（**节点 + 网络**，OS 内部、我方定标准）／B 业务侧（**设备 + 服务**，业务方主导定标准）；②**资源模型取消对外独立地位，并入节点属性，对外调度只认节点**；③**服务链＝服务集 + 关系**。<br>直接暴露点：M4 接入模板层 `os2.access.node/1` 已带 `capacity`，而内部 `node.schema.json` **没有**——`ACCESS_GUIDE` 的映射只能指向运行期 C++ 结构体 `NodeProfile`，内部模型里没有落点。**模板层跑在了内部模型前面。** |
| 影响面 | `contracts/models/`（删 1 类、改 3 类）+ 全部 node 真件 + `os2_validate`/`os2_extract`/投影脊柱 + C++ 规则表生成物 + 设计态三列。**运行期总线格式不变**（`Msg` 的 k=v 未动，主题/字典/错误码零改动）＝向后兼容 minor。 |

---

## 1 现状（改造前的五条事实）

1. **资源是独立 kind**：`resource.schema.json`（`node`/`cpu`/`mem_mib`/`instances`）+ 1 件样例
   `resource_compute-01-pool.json`，与 0720 决议"并入节点属性"直接冲突。
2. **node 模型没有容量**：`node.schema.json` 只有 `domain`/`profile`/`os`/`modules`/`networks`/`payload`；
   调度用的容量来自运行期 `ResourceReport` 上报，**设计态无落点**。
3. **关联关系全是裸字符串**：10 类模型里**只有 2 个字段**声明了 `x-ref-kind`
   （`service.interface`、`manifest.artifacts`）。`device.domainRef`/`device.networkRef`/
   `service.deploy`/`service.deviceRef`/`node.networks[]`/`chain.nodes[].service` 一律是
   裸串——**写错了没有任何门禁会红**。所谓"关联关系"停在文案层。
4. **服务间依赖只有模板层有**：M4 的 `os2.access.service/1` 声明了 `depends`，
   内部 `service.schema.json` **无此字段** → 模板↔内部映射有洞。
5. **设计态网络清单是前端手写常量**：`eth01/eth02/can01` 三行写死在 `showcase.hpp`，
   不来自 `network` 真件——所以删链后残留"五个设备 / 气囊、收放、投放"旧文案无人察觉。

---

## 2 提案（三层，缺一层就是形式主义）

### 2.1 层① 模型层：资源并入节点，删除 resource kind

- `node.schema.json` **新增** `capacity{cpu,mem_mib,gpu}` 与 `instances[]`
  （后者原为 `resource.instances`，语义与字段形状原样搬运）。
- **删除** `contracts/models/resource.schema.json` 与 `samples/resource_compute-01-pool.json`。
  容量真值搬进 6 件 node 真件；`compute-01` 的 pod1-3 搬进 `node.instances`。
- `device.commands` / `device.stateMachine` **字段级标 `deprecated`**（0720 边界②：
  命令面不再是我方交付面）。此前只有文件头注，字段本身没标——**所以设计态的手写模板里
  才会大剌剌写着 `<Command>`/`<StateMachine>`，拿刚剥离的东西当模板。**

> **为什么是删除而不是停用留痕**：负责人 2026-07-21 裁决"可以直接删除了"。
> 与 `R`/`D` 系列编号不同，`resource` kind 没有历史事故锚点依赖；且 `v1.0` 的证据链由
> git tag `v1.0` 与 `dist/v1.0/` 封版包保全，从 HEAD 删除不影响其可复现性。

### 2.2 层② 关系层：关联关系变成机器校验

**双轨，互补不重叠**：

| 轨 | 覆盖 | 机制 |
|---|---|---|
| **C++ 运行时** | 扁平载荷里的 `qt.*` 全名引用 | `x-ref-kind` → `--gen-cpp` 规则表 → `RefResolver`（opt-in `model.ref_check`） |
| **Python 门禁** | 设计态真件里的**叶名**引用 | `os2_validate` 交叉检，按 **kind + 叶名** 解析 |

之所以要第二轨：本仓真件里的引用一律写**叶名**（`deploy: "compute-01"`、
`networkRef: "can01"`、链步 `service: "sonar.switch"`），不是 `qt.*` 全名——因为
**运行期 profile 与调度用的就是叶名**。若为了让 x-ref 生效而把真件改成全名，会断运行链路。
所以按叶名解析，而不是改真件。服务名的点号写法（`sonar.switch`）与真件连字符名
（`sonar-switch`）互认。

新增 `x-ref-kind` 七处 + `service.depends[]` 新字段（对齐模板层）。

### 2.3 层③ 表现层：设计态三列＝二分的投影结果

- 投影 `os2_showcase_project.py` 升 v0.2，输出新增 **`grouping`** 表 + `networks` + `pools`：

  ```
  resourceSide : nodes · pools · networks     （OS 内部，我方定标准）
  businessSide : devices · services           （业务方主导，我方确认可接受）
  taskChains   : chains                       （服务集 + 关系）
  ```

- 前端三列**由 `grouping` 驱动**（列标题都回填自投影），网络清单/池清单改由真件渲染。
  这样模型分类一变列跟着变——**不会再出现"删了东西、文案还留着"**。
- 「模板」按钮从手写参考 XML 换成**四类接入模板真件**
  （`contracts/templates/access_*.schema.json`，经 `/export?f=access-tpl-*` 下发）。
  `node_profile.xml`/`device_model.xml`/`resource_profile.xml`/`network_profile.xml` 四份删除。
- 固定预留池（`reserved: exclusive`）**与可调度节点分列**——边界①"OS 看得见、动不了"
  在页面上有落点。

---

## 3 门禁增量（判负已验）

`os2_validate --selftest` 新增：

| 判据 | 类型 |
|---|---|
| 服务落位到不存在的节点 / 服务引用不存在的设备 / 服务依赖不存在的服务 | 判负 ×3 |
| 节点挂到不存在的网络 / 设备挂到不存在的节点 / 设备挂到不存在的网络 | 判负 ×3 |
| 链步引用不存在的服务 | 判负 ×1 |
| 叶名引用放行 / `qt.*` 全名放行 / 链步点号写法 ⟺ 真件连字符名 放行 | 正例 ×3 |

投影 `--selftest` 新增：**0720 二分分组自洽**（每组 kinds 都真在投影里，且没有哪类模型
未被任何组收编——漏一类＝设计态少一栏、无声掉数据）+ **固定预留池不混入可调度节点**。

> **实测结论值得记一笔**：存量 49 件真件在新引用门下**一次通过、零失败**。
> 关系本来就是对的——只是此前没有任何机制在查。

---

## 4 兼容性

| 面 | 影响 |
|---|---|
| 运行期总线 | **零**——主题/字典/错误码/`Msg` 格式全未动 |
| C++ 规则表 | 再生成（`device`/`node`/`service` 三行新增 refs，`resource` 行删除），门禁字节比对 |
| 存量真件 | node 真件加字段（加法）；`resource` 样例删除；网络真件补 `label` |
| 消费方 | `os2_extract` 的 Extract 输出 `resources` 字段 → 改为 `capacity` + `instances` |
| 契约版本 | `1.5.0` → **`1.6.0`**（加法演进，向后兼容 minor） |

---

## 5 不在本 RFC 内

- **`network` 的职责已由负责人 2026-07-21 定死，且刻意保持简单**：**网络不是我方设计的——客户有网络设计师。我方只把客户已有的拓扑/分区关系导入进来，用于服务与容器的运行配置检查**（例：某容器该绑到哪个 VLAN 或哪个物理口）。**分区口径＝VLAN**：填 `vlan` 即以 VLAN 为分区单元，不填即以物理接口为单元。据此**删除了 `isolation` 字段**——它与 `vlan` 表达同一件事，是我上一轮多造的一层维度（负责人原话：「不要做那么复杂」）。`plane` 保留但标明是**我方软总线归属**、不是客户网络属性。**交换机/路由器与故障传播分析仍归 M6**；本模型不承载转发路径。
- 业务侧建模标准本身（四要素/层级/隶属）——0720 边界③：**夸父与 AI 出方案**，不是我方范围。

---

## 6 落地件

| 类 | 文件 |
|---|---|
| 契约 | `contracts/VERSION`（1.6.0）· `models/node.schema.json`（+capacity/+instances/+networks x-ref）· `models/device.schema.json`（+2 x-ref、commands/stateMachine deprecated）· `models/service.schema.json`（+depends、+3 x-ref）· `models/resource.schema.json`（**删**）· `models/README.md` |
| 真件 | 6 件 node（+capacity，compute-01 +instances）· `node_ai-pool-01`（+capacity）· 3 件 network（+label）· `resource_compute-01-pool.json`（**删**） |
| 工具 | `os2_validate.py`（跨模型引用交叉检 + 10 条判负/正例自检 + Schema 数 9）· `os2_extract.py`（capacity/instances 取代 resources）· `os2_showcase_project.py` v0.2（grouping/networks/pools + 2 条自检） |
| 代码 | `model_schema_tables.hpp`（生成物）· `test_model_impl.cpp`（resource 用例改 chain 用例） |
| 演示 | `showcase.hpp`（三列改二分 + 列标题数据驱动 + 网络/池真件渲染 + 模板按钮换接入模板 + 删 4 份手写 XML）· `payloads.hpp`（九类 schema 导出 + 四类接入模板导出） |

## 更新记录

| 日期 | 摘要 |
|---|---|
| 2026-07-21 | 首版并同日实施落地（负责人三条批复：直接删 resource / 契约 bump 且发现问题直接改 / 三列改造不并入 M6）。 |
| 2026-07-21 | 续：**网络管理边界口径入模型**（负责人定：管到物理接口或 VLAN、以隔离为边界，路由器与故障传播放后面）——`network.schema` 加 `vlan`(1-4094) + `isolation`(physical\|vlan)，三件网络真件补 `isolation: physical`（compose 三网为独立网卡/总线、非 VLAN 划分，如实填）。 |
| 2026-07-21 | 再续：**网络模型按负责人口径收简**——删 `isolation`（与 `vlan` 重复，是多造的维度）；职责改写为「客户设计、我方导入、用于服务/容器运行配置检查」，**分区口径＝VLAN**；`plane` 标明为我方软总线归属而非客户网络属性。三件网络真件同步去 `isolation`。 |
