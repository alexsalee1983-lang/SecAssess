# SecAssess 架构设计说明

> **文档用途**：本文件是「网络安全评估工具箱」的架构参考，供 Claude Code 作为开发上下文使用。
> **版本**：v0.3　**定位**：授权范围内的防御性安全评估平台（评估 / 核查 / 合规，非攻击）。
> **技术路线**：A 方案 —— 运行时适配器接入（不打包第三方引擎二进制，经 Scanner Adapter 动态调度 MCP）。

---

## 0. 给 Claude Code 的开发须知（必读）

构建本项目时，以下为**不可违背的约束**：

1. **非阻塞优先**：任何长耗时动作（扫描、验证）必须异步化，提交即返回 job_id，后台执行，前端轮询/SSE。严禁同步阻塞。详见 §11。
2. **适配器隔离**：业务逻辑只依赖 `ScannerAdapter` 抽象接口，不直接调用具体 MCP / 引擎。
3. **授权前置（fail-closed）**：任何主动动作前必须过 `ScopeGate`，越界即拒绝或转 HITL。无 `scope_token` 不执行。
4. **单一事实源**：所有发现归一化为 `NormalizedFinding`，写入 Asset Graph / Evidence Store，不在内存/上下文堆积。
5. **人机协同可控**：大模型驱动工具，但 Scope Gate 与 HITL 是回路内硬闸门，模型不可自行跳过。
6. **大模型不当裁判**：可利用性验证必须由独立的确定性验证器完成，而非 LLM（见 §10.2）。
7. **每个模块配测试**：核心逻辑（异步内核、授权闸门、契约）必须有单元测试。

---

## 1. 范围与定位

- **纳入（6+1 功能）**：① 资产测绘　② 漏洞扫描　③ 配置基线　④ 攻击面 EASM　⑤ 钓鱼演练　⑥ 风险/合规审计；⑦ Web/API 评估（可选）。
- **暂不做**：代码供应链评估、云安全评估。
- **定位**：面向企业安全团队与评估服务，所有动作以客户授权为前提，强调评估、核查与合规。

---

## 2. 设计红线与供应链底线

### 四条设计红线
| # | 红线 | 含义 |
|---|---|---|
| ① | 适配器隔离 | 业务 Agent 不直接调用具体 MCP，一律经抽象 Scanner Adapter；换引擎不改 Agent。 |
| ② | 授权前置 | 主动动作前必过 Scope Gate 并签发 token；无令牌不执行。 |
| ③ | 单一事实源 | 所有发现归一化为 NormalizedFinding，写入事实源，各 Agent 订阅同源。 |
| ④ | 人机协同可控 | LLM 以 Harness 回路驱动工具，但 Scope Gate 与 HITL 是硬闸门。 |

### 供应链底线
- 开源引擎 → **自研封装**（固定版本、过 CIS MCP Server Benchmark 审查后上线）；
- 商业引擎（Nessus/Burp）→ 仅 **API 对接**、用客户自有 license、不内置二进制；
- 第三方 skill / 现成 MCP hub → 可参考加速原型，**不直接吞入生产**。

---

## 3. 总体架构（7 层 + 2 横切）

```
┌─ L6 输出层 ──────────────────────────────────────────────┐
│  控制台 Dashboard │ 报告引擎（Word/PDF/PPT/合规矩阵）      │
├─ L1 交互/协同层 ─────────────────────────────────────────┤
│  自然语言 Copilot ◄──► 评估人员   （NL 指令 / 结果问答）   │
├─ L2 编排·推理层（★大模型 Harness）──────────────────────┤
│  Orchestrator-LLM：意图理解 → 任务规划 → 工具选择          │
│  plan→act→observe 回路 · 以 Asset Graph/Evidence 为外部记忆│
│  内置硬闸门：Scope Gate 授权校验 · HITL 人工审批状态机      │
├─ L3 业务 Agent 层（每个可为 planner-executor 子模型）─────┤
│ ①资产 ②漏洞 ③基线 ④EASM ⑤钓鱼 ⑥合规 ⑦Web/API            │
├─ L4 能力/适配层 ─────────────────────────────────────────┤
│  Scanner Adapter（抽象接口）→ MCP 工具 / 商业 API / Connector│
├─ L5 数据·知识层 ─────────────────────────────────────────┤
│  Asset Graph │ Evidence Store │ Vault │ 知识库(模板/框架/   │
│  历史数据，供 LLM 做 RAG 上下文检索)                        │
├─ L0 输入/接口层（六类评估输入，标准化接入）──────────────┤
│  授权·约束 │ 资产·上下文 │ 凭证 │ 被动采集 │ 既有数据 │ 人工 │
└──────────────────────────────────────────────────────────┘
  横切① Guardrail/Policy：授权·速率·脆弱资产保护·危险动作拦截
  横切② Audit Log：全程留痕（谁·何时·对谁·做了什么·依据）
```

| 层 | 职责 |
|---|---|
| L6 输出层 | 态势控制台 + 报告引擎。 |
| L1 交互层 | 自然语言 Copilot。 |
| L2 推理层 | Orchestrator-LLM，Harness 回路；内置 Scope Gate 与 HITL。 |
| L3 Agent 层 | 七个业务 Agent，可各自为 planner-executor 子模型。 |
| L4 适配层 | Scanner Adapter → MCP / 商业 API / Connector。 |
| L5 数据知识层 | Asset Graph、Evidence Store、Vault、知识库（RAG）。 |
| L0 输入层 | 六类评估输入标准化接入（§5）。 |

---

## 4. 大模型协同 / Harness 工程

大模型是编排回路的驱动者，运行在 `plan → act → observe` 回路：

```
评估人员自然语言指令
   │
   ▼
[plan]   大模型理解意图 → 分解任务 → 选择工具与目标
   │
   ▼
[gate]   Scope Gate 授权校验（硬闸门）── 越界/高敏 → HITL 审批
   │ 通过并签发 scope_token
   ▼
[act]    经 Scanner Adapter 调用 MCP 工具（带凭证引用）
   │
   ▼
[observe] 读取归一化结果 → 决定下一步
   │  （上下文装不下全部发现：以 Asset Graph/Evidence Store 为外部记忆，按需检索）
   ▼
汇聚 → 报告 / 继续下一轮
```

- **两级推理**：顶层 Orchestrator-LLM 统筹；各业务 Agent 可内嵌 planner-executor 子模型。
- **外部记忆**：模型上下文装不下全部发现，用事实源做外部记忆，RAG 检索客户上下文（基线模板/合规框架/历史数据）。

---

## 5. 输入层：六类评估输入

单靠主动扫描仅覆盖 40–60%，需多源证据融合。前两类关系安全底线。

| 输入类别 | 接入方式 | 关键内容 | 供给 Agent |
|---|---|---|---|
| ① 授权与交战规则 | 人工录入 | 授权书 · 范围(IP/域/时间窗) · RoE · 免扫清单 · 紧急联系人 | Scope Gate · 全体 |
| ② 资产与上下文 | CMDB / 云 API 连接器 | CMDB · 云资产 · 业务重要性分级 · 数据分类 | ① 资产 · ⑥ 合规 |
| ③ 凭证 | Vault 连接器 | 认证扫描 · 主机采集 · API Token · 云 Key（临时令牌） | ②③⑤⑦ |
| ④ 被动采集 | 旁路 / 日志连接器 | 流量镜像(NetFlow/SPAN) · DNS/DHCP · SIEM 日志 | ① 资产 · ④ EASM |
| ⑤ 既有安全数据 | 文件导入 | 历史扫描(Nessus) · SBOM · 补丁基线 · 既往报告 | ② 漏洞 · ⑥ 合规 |
| ⑥ 人工复核闭环 | 录入接口 | 误报标记 · 风险接受 · 整改状态回填 | 全体 → 事实源 |

**接入开发顺序**（前两项不就绪不启动主动评估）：
`① 授权与交战规则 → ② 凭证 Vault → ③ 资产/上下文 CMDB → ④ 被动采集 → ⑤ 既有数据导入 → ⑥ 复核闭环`

---

## 6. 核心契约（代码）

### 6.1 Scanner Adapter 抽象接口
业务 Agent 只认这套方法；`scan()` 必须协作式非阻塞（周期性 await，可取消）。

```python
class ScannerAdapter(abc.ABC):
    name: str
    @abc.abstractmethod
    def capability(self) -> Capability: ...        # engine, scan_types, needs_credential, intrusive_level
    @abc.abstractmethod
    async def scan(self, request: ScanRequest,
                   on_progress: Callable[[float, str], None]) -> list[NormalizedFinding]: ...
```

### 6.2 ScanRequest（统一入参）
```python
@dataclass
class ScanRequest:
    targets: list[str]
    scan_type: ScanType                 # port_discovery|vuln|config_baseline|exposure|web|phishing
    scope_token: str                    # 必填：ScopeGate 签发，无令牌不扫描
    credential_ref: str | None = None   # vault://... 引用，永不传明文
    options: dict = {}
    rate_limit: RateLimit = RateLimit(pps=1000, concurrency=50)
    scan_id: str = <auto>
```

### 6.3 NormalizedFinding（单一事实源契约）
```python
@dataclass
class NormalizedFinding:
    finding_id, scan_id
    source: { adapter, engine, engine_version,
              channel: active_scan|cmdb|cloud_api|passive|manual }
    asset_ref                            # Asset Graph 节点
    target, category                     # asset|vulnerability|misconfig|exposure|compliance
    title, severity                      # critical|high|medium|low|info
    cvss{version,score,vector}, cve[]
    confidence                           # confirmed|firm|tentative（误报抑制依据）
    evidence_ref, collected_at, raw_ref, remediation
```

### 6.4 统一调用链
```
Orchestrator-LLM ─(Scope Gate 授权校验)─► 拦截未授权/高敏 → HITL
   │ 签发 scope_token
   ▼
业务 Agent → 读 Asset Graph 取目标 → 向 Vault 取凭证
   ▼
Scanner Adapter（抽象接口 / 速率限制 / 结果归一化）
   ▼
具体 MCP（nuclei-mcp / nmap-mcp / openscap-mcp ...）
   ▼
归一化 → NormalizedFinding → Evidence Store + Asset Graph
```

---

## 7. 业务 Agent 与 MCP 对接

| 功能 Agent | 对接引擎 | MCP 来源策略 | 调用位置 |
|---|---|---|---|
| ① 资产测绘 | nmap · masscan · httpx | 自研封装 | AssetDiscovery → Adapter → Asset Graph |
| ② 漏洞扫描 | nuclei · OpenVAS；Nessus(商业) | nuclei 自研；Nessus 商业 API | 订阅 Asset Graph，凭证取 Vault |
| ③ 配置基线 | OpenSCAP · Lynis · InSpec | 自研封装 | → 主机采集器(SSH/WinRM) → openscap-mcp |
| ④ EASM | subfinder · gowitness · naabu | 自研封装 | Adapter（只读）；TI 走 Shodan/Censys |
| ⑤ 钓鱼演练 | GoPhish | 必须自研封装 | 发送前强制 HITL 审批 |
| ⑥ 合规审计 | 映射引擎 | 自研 | 消费 ①~⑤ + 人工证据，映射控制框架 |
| ⑦ Web/API | ZAP · nuclei · ffuf；Burp(商业) | ZAP/nuclei 自研；Burp 商业 | 输入 OpenAPI + Token |

**横切支撑 MCP**：`vault-mcp`（凭证）、`graph-mcp`(Neo4j，Asset Graph)、报告引擎。

**各 Adapter options 草案（节选）**：
```
nmap     { profile:quick|default|deep, ports, service_det } → asset
nuclei   { templates[], template_ver(pin), auth{credential_ref}, severity[] } → vulnerability
openscap 前置主机采集(SSH/WinRM)；{ benchmark:CIS, profile, host_ref } → misconfig
easm     intrusive_level:readonly；{ seed_domains[], modules[], ti_enrich } → exposure
gophish  { campaign, targets_ref, approval:"REQUIRED" }  ← 唯一对外发信
webapi   { spec_ref(OpenAPI), base_url, auth{credential_ref}, engines[] }
```

---

## 8. 治理与安全

### 8.1 角色权限（RBAC）——职责分离
| 角色 | 查看 | 启动扫描 | 审批 | 接入/凭证 | 报告 |
|---|:-:|:-:|:-:|:-:|:-:|
| 评估负责人 | ✓ | ✓ | ✓ | ✓ | ✓ |
| 评估员 | ✓ | ✓ | — | — | ✓ |
| 审批人 | ✓ | — | ✓ | — | — |
| 客户（只读） | ✓ | — | — | — | — |

### 8.2 HITL 人工审批触发规则（回路内硬闸门）
| 触发条件 | 说明 |
|---|---|
| 对外动作 | 钓鱼发信、社工，任何向真实人员/外部发送 |
| 侵入式动作 | 漏洞可利用性验证、deep 扫描、对脆弱/OT 资产主动探测 |
| 超授权范围 | 目标不在授权清单、命中免扫清单 |
| 窗口/速率越界 | 维护窗口外执行、超约定速率 |
| 高危结论 | critical/high 发现的复核与风险接受 |
| 凭证升级 | 使用更高权限凭证或访问敏感系统 |

### 8.3 Scope Gate
主动动作前校验目标在授权范围内（IP/域白名单 + 时间窗 + 免扫清单优先），通过后签发限时 `scope_token`。**fail-closed**：任一目标越界整体拒绝。

### 8.4 事实看板
统一事实源可视化：来源通道覆盖、发现分类、置信度分布（误报治理）、每条 NormalizedFinding 的证据链溯源（通道→引擎→时间→原始输出→资产节点）。

---

## 9. 架构缺口与补强（12 项，三档）

**第一档 · 必补**：① 分布式扫描节点/采集器拓扑；② 大模型安全（注入防护+工具调用授权）；③ 工具自身加固+证据链可采性；④ 多租户/项目数据隔离。
**第二档 · 工程完整性**：⑤ 评估生命周期工作流+复测闭环；⑥ 风险评分模型；⑦ 去重/资产身份归并引擎；⑧ 任务调度与扩展性。
**第三档 · 集成与运营**：⑨ 整改闭环/工单集成；⑩ 外部集成(SSO/SIEM/ITSM)；⑪ 内容更新流水线；⑫ 平台可观测性。
**最先补三项**：①扫描节点拓扑、②大模型安全、⑤评估生命周期工作流。

---

## 10. 对标业界顶级的能力升级

### 10.1 攻击路径分析 / 暴露图
在 Asset Graph 上扩展为 Exposure Graph：
```
nodes: asset | identity | credential | service
edges: reachable_to | exploitable_via | has_privilege | trusts
query: shortest_path(entry → crown_jewel); rank_by choke_point_score
```
产出：攻击路径图 + choke-point 优先修复清单。依赖身份/权限数据 + 业务重要性分级。

### 10.2 可利用性验证引擎（AI 发现 / 确定性验证分离）
```
[Agent/LLM] 提出候选可利用性假设
   → [Validator（确定性，独立于 LLM）] 受控验证：无损/沙箱/PoC 签名（验证“可达可利用”而非“实际利用”）
   → 侵入式验证 → HITL 审批
   → 回写 confidence=confirmed + evidence_ref
```
一举两得：同时落实缺口②（LLM 不当裁判）。收益：误报抑制 + 结果可采信 + 安全边界。

### 10.3 CTEM 持续化（五阶段映射）
| CTEM 阶段 | 映射到本架构 |
|---|---|
| Scoping | Scope Gate + 授权/资产范围 |
| Discovery | ① 资产 + ④ EASM + 被动采集 |
| Prioritization | 风险评分 + 威胁情报(CISA KEV/EPSS/活跃技战术) |
| Validation | 10.2 可利用性验证 |
| Mobilization | 整改闭环/工单 + 复测 |

持续触发：配置漂移/新部署/新情报到达时自动触发重评估。

---

## 11. 非阻塞设计（避免界面卡死）—— 全程约束

1. **提交即返回**：扫描提交立即返回 job_id，执行在后台 asyncio 任务 / 分布式 worker。
2. **轮询 + 流式**：状态用 `GET /scans/{id}` 轮询或 `/stream` (SSE) 推送，前端增量刷新。
3. **并发上限**：信号量限制同时运行的扫描数，超额排队。
4. **可取消 + 超时**：每任务支持协作式取消与超时，失败隔离在 job 内，不拖垮平台。
5. **数据外置记忆**：发现写入 Evidence Store / Asset Graph，不在内存/上下文堆积。

**JobManager 行为契约**：
```
submit(adapter, request) -> job_id        # 非阻塞，立即返回
status(job_id) -> {state, progress, ...}  # queued|running|done|failed|cancelled
results(job_id) -> [NormalizedFinding]
cancel(job_id) -> bool
stream(job_id) -> async iterator(JobView) # SSE
```

---

## 12. 代码骨架（M0 已落地）

```
secassess/
  models.py              核心契约：ScanRequest / NormalizedFinding（单一事实源）
  adapters/
    base.py              ScannerAdapter 抽象接口（上层只认它）
    mock_nmap.py         Mock 适配器（验证内核，后续替换为真实 MCP 封装）
  core/
    jobs.py              ★ 异步非阻塞 JobManager（提交即返回/并发/取消/超时/SSE）
    scope_gate.py        Scope Gate 授权闸门（fail-closed）
    orchestrator.py      Orchestrator（M0 最小编排；M2 扩展为 LLM Harness 回路）
  api/app.py             可选 FastAPI 层（非阻塞 REST + SSE）
demo.py                  端到端演示（提交即返回 + 并发 + 进度轮询）
tests/                   单元测试（标准库 unittest）
```

**扩展点**：
- 新引擎 → 实现 `ScannerAdapter`（封装 nmap-mcp / nuclei-mcp / openscap-mcp），上层不改。
- 分布式 → `JobManager` 内存 store 换 Redis，执行派发 Celery/RQ，接口不变。
- 授权 → `ScopePolicy` 从 L0 输入层加载。

---

## 13. 里程碑

| 里程碑 | 目标 | 出口标准 |
|---|---|---|
| **M0 · 异步内核与契约** ✅ | 地基 | submit 瞬间返回、后台并发、轮询/SSE；测试全绿 |
| **M1 · 主干三件套** | 真实扫描 | 资产→漏洞→基线在同一事实源贯通并出报告 |
| **M2 · 编排与协同** | 大脑 | 自然语言驱动完整评估；高敏动作卡审批 |
| **M3 · 治理与事实源** | 可信 | 多源去重合并；证据链可追溯；权限门控生效 |
| **M4 · 对标顶级升级** | 差异化 | 攻击路径+choke-point；验证降误报；持续触发 |
| **M5 · 企业化** | 可交付 | 多租户；分布式；集成；自身过 CIS 基线 |

---

## 14. 技术选型与开发约定（建议）

- **后端**：Python + FastAPI（async）；asyncio 任务 → 后续 Redis + Celery/RQ 分布式。
- **数据**：Asset Graph 用 Neo4j；Evidence Store 用 PostgreSQL/对象存储；凭证用 HashiCorp Vault。
- **MCP**：各引擎封装为 MCP server（Python MCP SDK），经 Scanner Adapter 调用；固定版本、过 CIS MCP Server Benchmark。
- **前端**：控制台（态势总览 / 7 Agent / 事实看板 / 审批队列 / 输入接入），消费非阻塞 REST + SSE。
- **约定**：所有长任务异步非阻塞；适配器模式解耦引擎；授权 fail-closed；核心逻辑配单元测试；边界处兜底异常，错误进 job 不崩平台。

---

## 15. 待确认事项

1. 目标合规框架优先级（等保 2.0 / ISO 27001 / CIS）→ 决定合规映射范围。
2. 凭证托管选型（自建 Vault 还是对接客户 PAM/KMS）。
3. Asset Graph 落库选型（Neo4j vs 既有 CMDB 扩展）。
4. 部署形态（客户本地 / 私有化 / 混合）→ 直接影响扫描节点拓扑。
5. 商业引擎（Nessus/Burp）是否纳入首期 → 取决于客户 license 现状。
