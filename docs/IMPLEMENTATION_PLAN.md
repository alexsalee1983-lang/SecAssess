# SecAssess 实施计划（M0 + M1）与完成标准

依据：[ARCHITECTURE.md](ARCHITECTURE.md) v0.3（§6 契约、§8 治理、§11 非阻塞、§12 骨架、§13 里程碑）。
约束：
- 引擎接入：Mock 加通用 MCP 适配器。
- 存储：SQLite，放在接口之后，可替换。
- 本轮不做前端，只提供 API。
- Mock 只产出合成占位发现。

---

## 0. 完成标准的总规则

**一个步骤算"做完了"，必须同时满足以下四条：**

1. 该步骤「完成标准」里列出的每条命令都**返回 0**。
2. 之前所有步骤的测试仍然通过，即 `python -m pytest tests -q` 返回 0。完成一步不能破坏前面的步骤。
3. `python -m compileall -q secassess` 返回 0，保证没有语法错误。
4. 代码已提交，并推送到 `claude/gallant-gauss-auov0v`。

**环境准备**（只需一次）：

```bash
pip install -e ".[dev,api]"      # dev = pytest；api = fastapi + uvicorn + httpx
```

测试用标准库 `unittest` 编写，所以同时兼容 pytest 和 `python -m unittest`；在没有安装 pytest 的环境里，可以用 `python -m unittest tests.test_xxx` 代替。

**测试里禁止**：真实网络流量、`time.sleep`，以及依赖外部服务（Vault、Neo4j、真实扫描引擎）。

---

## 1. 现状（已提交）

| 文件 | 内容 |
|---|---|
| `secassess/models.py` | §6 契约：枚举、RateLimit、ScanRequest（校验）、NormalizedFinding（fingerprint）、Capability |
| `secassess/adapters/base.py` | ScannerAdapter、AdapterRegistry、AdapterError |
| `secassess/adapters/mock_nmap.py` | 确定性端口发现（CIDR 展开，无网络） |
| `secassess/adapters/mock_placeholder.py` | vuln / config_baseline 的合成占位发现 |

⚠️ 以上文件目前**没有测试**，所以第 1 步要先给它们补上测试。

---

## 2. 分步计划与完成标准

### 第 1 步：工程骨架 + 契约与 Mock 适配器的测试
**文件**
- `pyproject.toml`：零运行时依赖；extras 分为 `dev`（pytest）、`api`（fastapi、uvicorn、httpx）、`docx`（python-docx）。
- `tests/__init__.py`
- `tests/test_models.py`
- `tests/test_mock_adapters.py`
- `.github/workflows/ci.yml`

**完成标准**
- `pip install -e ".[dev]"` 返回 0。
- `python -m pytest tests/test_models.py -q` 返回 0，至少覆盖以下用例：
  - 空目标被拒。
  - 无 `scope_token` 被拒。
  - 明文凭证被拒（凭证必须是 `vault://` 引用）。
  - 以 `-` 开头或含 `;` 的目标被拒。
  - fingerprint 稳定，且与扫描引擎无关。
  - `to_dict` / `from_dict` 往返一致。
- `python -m pytest tests/test_mock_adapters.py -q` 返回 0，至少覆盖以下用例：
  - 相同输入两次扫描结果一致。
  - CIDR 展开的主机数不超过上限。
  - 扫描中途调用 `task.cancel()` 后能抛出 `CancelledError`。
  - 进度回调单调不减，最终达到 1.0。
- CI 工作流文件存在，内容是运行 `python -m pytest tests -q`。

### 第 2 步：HITL 审批状态机
**文件**：`secassess/core/hitl.py`、`tests/test_hitl.py`

**完成标准**：`python -m pytest tests/test_hitl.py -q` 返回 0，至少覆盖以下用例：
- 申请人审批自己的申请时抛出 `ApprovalError`（职责分离）。
- 已批准的动作在内容被修改后，consume 失败。
- 同一个审批只能 consume 一次，第二次失败。
- 超过 TTL 后状态变为 `expired`，不能再审批或兑现（时钟可注入，不使用真实的 sleep）。
- 已拒绝的审批不能再次批准。

### 第 3 步：Scope Gate 授权闸门
**文件**：`secassess/core/scope_gate.py`、`tests/test_scope_gate.py`

**完成标准**：`python -m pytest tests/test_scope_gate.py -q` 返回 0，至少覆盖以下用例：
- 目标在 CIDR 或域白名单内（含 `*.` 通配）时允许，并签发令牌。
- 多个目标中只要有一个越界，就**整体拒绝**（fail-closed）。
- 免扫清单优先：单个 IP 命中被拒；**CIDR 目标与免扫段只要有部分交集就被拒**。
- 项目没有配置授权策略时被拒；授权未生效或已过期时被拒；RoE 不允许的扫描类型被拒。
- 以下情况转 HITL：`profile=deep`、侵入式动作、维护窗口外、超出约定速率、脆弱资产、高权限凭证。
- `verify` 在以下情况抛出 `ScopeViolation`：令牌被篡改、已过期、目标超出令牌范围、项目不符、扫描类型不符、已吊销、执行时目标命中免扫清单。

### 第 4 步：RBAC + 审计日志
**文件**：`secassess/core/rbac.py`、`secassess/core/audit.py`、`tests/test_rbac_audit.py`

**完成标准**：`python -m pytest tests/test_rbac_audit.py -q` 返回 0，至少覆盖以下用例：
- §8.1 权限矩阵的 4 个角色 × 5 种权限，逐项断言与文档表格一致。
- 用户访问未授权的项目时，抛出 `PermissionDenied`。
- 正常写入 N 条审计记录后 `verify_chain()` 为 True；直接用 SQL 篡改其中一条后为 False。

### 第 5 步：数据层（Vault / Evidence Store / Asset Graph / FactStore）
**文件**：
- `secassess/data/vault.py`、`secassess/data/evidence.py`、`secassess/data/asset_graph.py`、`secassess/data/facts.py`
- 测试：`tests/test_vault.py`、`tests/test_evidence.py`、`tests/test_asset_graph.py`

**完成标准**：`python -m pytest tests/test_vault.py tests/test_evidence.py tests/test_asset_graph.py -q` 返回 0，至少覆盖以下用例：
- `repr(Secret)` 和 `str(Secret)` 都不包含明文；非 `vault://` 引用或不存在的引用会抛出 `VaultError`。
- 两个不同引擎报告同一个问题时，合并为 1 条记录：`sources` 有 2 条，置信度和严重性取较高值。
- 人工复核状态（如 `false_positive`）在新的扫描结果合并进来后仍然保留。
- `put_raw` 写入后 `get_raw` 能读回；内容被篡改后 `get_raw` 抛出完整性错误。
- 同一资产以不同写法写入（大小写不同、末尾带点）时，只产生 1 个节点。
- FactStore 写入发现后，`asset_ref` 已回填，并且 service 节点已建立。
- 所有存储都同时支持 `:memory:` 和文件路径两种模式。

### 第 6 步：★ 异步 JobManager（§11）
**文件**：`secassess/core/jobs.py`、`tests/test_jobs.py`

**完成标准**：`python -m pytest tests/test_jobs.py -q` 返回 0，至少覆盖以下用例：
- **非阻塞**：对一个耗时 2 秒的适配器调用 `submit`，在 50ms 内返回 job_id。
- **并发上限**：`max_concurrent=2` 时同时提交 5 个任务，观测到的最大并发数等于 2。
- **取消**：排队中和运行中的任务都能取消，最终状态为 `cancelled`；已完成的任务调用 `cancel` 返回 False。
- **超时**：最终状态为 `failed`，错误信息中包含 `timeout`。
- **错误隔离**：适配器抛出异常时，该任务状态为 `failed`，同时提交的其它任务仍然 `done`。
- **流式状态**：`stream()` 产出的序列以终态结束，且 progress 单调不减。
- **fail-closed**：没有配置校验器、令牌非法、或适配器不支持该扫描类型时，`submit` 同步抛出异常，且不创建任务。
- `results()` 从 sink 读取，与适配器的输出一致。

### 第 7 步：通用 MCP 适配器
**文件**：`secassess/adapters/mcp.py`、`tests/fake_mcp_server.py`（纯标准库实现的 stdio MCP 服务）、`tests/test_mcp_adapter.py`

**完成标准**：`python -m pytest tests/test_mcp_adapter.py -q` 返回 0，至少覆盖以下用例：
- 依次完成握手 `initialize` → `notifications/initialized` → `tools/call`，并返回归一化后的发现。
- `notifications/progress` 被转发到 on_progress。
- 假服务返回不在请求目标内的结果时，这些结果被丢弃，且丢弃数可以查询。
- 工具返回 `isError` 时抛出 `MCPError`；服务进程提前退出时抛出 `MCPError`。
- 取消后子进程已结束（`returncode` 不为 None）。
- 有 `credential_ref` 时，凭证从 Vault 解析后才传给工具，且凭证明文不出现在任何发现中。

### 第 8 步：业务 Agent + L0 输入
**文件**：`secassess/agents/base.py`、`asset.py`、`vuln.py`、`baseline.py`；`secassess/inputs/scope_loader.py`；测试 `tests/test_agents.py`

**完成标准**：`python -m pytest tests/test_agents.py -q` 返回 0，至少覆盖以下用例：
- 当真实适配器可用时优先选它，不可用时退回 mock。
- `VulnScanAgent` 在没有显式目标时，从图谱的 service 节点取 `host:port`。
- `BaselineAgent` 在缺少 `credential_ref` 时抛出 `ValueError`。
- `profile=deep` 的侵入等级被提升为 `intrusive`。
- `load_policy` 能加载 `examples/scope.json`。
- `readiness()` 在缺少授权策略或凭证时返回未就绪，并给出原因。

### 第 9 步：编排器（M1 主干链路）
**文件**：`secassess/core/orchestrator.py`、`tests/test_orchestrator.py`

**完成标准**：`python -m pytest tests/test_orchestrator.py -q` 返回 0，至少覆盖以下用例：
- **主干贯通**：`run_pipeline` 依次跑完资产 → 漏洞 + 基线；结束后 EvidenceStore 中同时存在 `asset`、`vulnerability`、`misconfig` 三类发现，并且都挂到了同一个 Asset Graph。
- **审批流程**：deep 扫描先返回 `pending_approval`，审批人批准后，`resume` 提交任务并完成；申请人自己审批会失败。
- 越界目标返回 `denied`，不会产生任何任务。
- 不具备 scan 权限的角色（client、approver）调用 `execute` 会失败。
- 每次 execute、审批、提交都在审计日志中留痕，且最终 `verify_chain()` 为 True。

### 第 10 步：报告引擎
**文件**：`secassess/reports/engine.py`、`tests/test_reports.py`

**完成标准**：`python -m pytest tests/test_reports.py -q` 返回 0，至少覆盖以下用例：
- Markdown 和 HTML 中包含：项目名、授权书编号、资产数、按严重性统计的数量、每条发现的证据链（通道→引擎→时间→资产）。
- HTML 会转义发现标题中的 `<script>`，防止 XSS。
- 安装了 python-docx 时生成的 `.docx` 能被重新打开；未安装时该用例被跳过而不是失败。

### 第 11 步：平台装配 + REST/SSE API
**文件**：`secassess/platform.py`、`secassess/api/app.py`、`secassess/__main__.py`、`examples/scope.json`、`examples/mcp_adapters.json`、`tests/test_api.py`

**完成标准**
- `python -m pytest tests/test_api.py -q` 返回 0（未安装 fastapi 时整个文件跳过）。用 TestClient 至少覆盖以下用例：
  - 没有或错误的 `X-API-Key` 返回 401；权限不足返回 403。
  - `POST /scans` 返回 **202** 和 `job_id`；越界返回 403；deep 扫描返回 202 和 `approval_id`。
  - 能从 `GET /scans/{id}` 轮询到 `done`；`/stream` 返回 `text/event-stream`，最后一个事件是终态。
  - 对 critical/high 发现做风险接受（`PATCH /findings/{id}` 设为 `accepted`）需要 approve 权限。
  - `GET /reports/{pid}?format=md` 返回 200。
- `python -m secassess --help` 返回 0。

### 第 12 步：端到端演示 + 文档
**文件**：`demo.py`、`README.md`、`scripts/smoke_api.sh`

**完成标准**
- `python demo.py` **返回 0**，输出中依次出现：
  - submit 耗时（小于 50ms）
  - 并发进度
  - `pending_approval` → 批准 → `done`
  - 报告文件路径
- `bash scripts/smoke_api.sh` 返回 0。脚本会：
  1. 后台启动 `python -m secassess serve`；
  2. 用 curl 依次设置 scope → 提交扫描 → 轮询到 `done` → 拉取 findings 和报告；
  3. 关闭服务。
- README 中的每条命令都与上面的命令一致，可以直接复制运行。

---

## 3. M0 + M1 整体验收（全部满足才算本轮完成）

| # | 命令或检查 | 要求 |
|---|---|---|
| 1 | `python -m compileall -q secassess` | 返回 0 |
| 2 | `python -m pytest tests -q` | 返回 0，零失败（skip 仅限缺少可选依赖的情况） |
| 3 | `python -m unittest discover -s tests` | 返回 0（在无 pytest 的环境中同样成立） |
| 4 | `python demo.py` | 返回 0 |
| 5 | `bash scripts/smoke_api.sh` | 返回 0 |
| 6 | 远端分支 CI | 最新提交为绿色 |
| 7 | 对照 ARCHITECTURE.md | §13 中 M0 的出口标准（submit 瞬间返回、后台并发、轮询/SSE、测试全绿）与 M1 的出口标准（资产→漏洞→基线在同一事实源贯通并出报告）都有对应的测试用例 |

---

# 第二阶段：M2 – M4 实施计划与完成标准

沿用第 0 节的总规则：每一步列出的命令都返回 0；全量测试仍然通过；compileall 和 ruff 通过；代码已提交推送，CI 为绿色。
M5（企业化：分布式扫描节点、SSO/SIEM/ITSM 集成、部署形态）依赖架构文档 §15 的待确认事项和基础设施选型，**做到 M5 前先停下来请用户确认**。

## M2 · 编排与协同（自然语言驱动完整评估，高敏动作卡审批）

### 第 13 步：规划器接口 + 规则规划器
**文件**：`secassess/copilot/planner.py`（`PlannedStep`、`Planner` 协议、`RuleBasedPlanner`）、`tests/test_planner.py`

**完成标准**：`python -m pytest tests/test_planner.py -q` 返回 0，至少覆盖：
- 从中文或英文指令中提取 IP、CIDR、域名、URL 目标。
- 关键词映射到 agent：资产/端口 → asset，漏洞 → vuln，基线 → baseline；"全面评估"展开为 asset → vuln → baseline。
- "深度"一词映射为 `profile=deep`。
- 指令中没有目标时返回空计划并给出原因。
- 输出的 agent 名不在白名单内时被丢弃。

### 第 14 步：LLM 规划器（Claude）+ 大模型安全
**文件**：`secassess/copilot/llm.py`（`ClaudePlanner`，可选依赖 `anthropic`）、`tests/test_llm_planner.py`

**完成标准**：`python -m pytest tests/test_llm_planner.py -q` 返回 0，用假客户端，不调用真实 API，至少覆盖：
- 模型的工具调用结果按严格 schema 校验，非法 agent、非法 option、超长目标列表都被拒绝。
- 模型拿不到也无法生成 scope_token 或 approval_id；它的输出只是"提议"，必须经过 Scope Gate。
- 事实源内容作为不可信数据放入 `<untrusted_data>` 区块，注入文本不会改变计划。
- 遇到 API 错误、`refusal` 或没有工具调用时，回退到规则规划器。
- 未安装 `anthropic` 或没有凭证时，自动使用规则规划器。

### 第 15 步：Copilot Harness 回路 + 结果问答 + API
**文件**：`secassess/copilot/harness.py`、`secassess/copilot/qa.py`、`secassess/api/app.py`（`/copilot`）、`tests/test_copilot.py`

**完成标准**：`python -m pytest tests/test_copilot.py -q` 返回 0，至少覆盖：
- 一句"对 192.0.2.0/28 做全面评估"能自动走完 plan → gate → act → observe，事实源中出现三类发现。
- 深度扫描在 HITL 处暂停（状态 `waiting_approval`），审批后 `continue` 能继续。
- 越界目标被 Gate 拒绝，回路如实报告且不会重试绕过。
- 循环次数有上限（max_iterations）。
- 问答只从事实源检索并返回带 finding_id 的引用。
- API：`POST /copilot/runs` 返回 202；`GET /copilot/runs/{id}?wait=` 可查询；`POST /copilot/ask` 返回结果。

### 第 16 步：其余业务 Agent（④ EASM、⑤ 钓鱼演练、⑦ Web/API）
**文件**：`secassess/agents/easm.py`、`phishing.py`、`webapi.py`；`secassess/adapters/mock_placeholder.py` 扩展；`secassess/adapters/openapi_review.py`（OpenAPI 静态审查，不发请求）；`tests/test_agents_ext.py`

**完成标准**：`python -m pytest tests/test_agents_ext.py -q` 返回 0，至少覆盖：
- EASM 的侵入等级为 readonly，免扫清单仍然生效。
- 钓鱼演练的侵入等级为 external，**任何情况下都必须先审批**；适配器在没有审批标记时自身也拒绝执行（纵深防御）。
- OpenAPI 静态审查能识别以下问题：缺少安全要求的接口、`http://` 服务器地址、未声明认证方案；整个过程不发出任何网络请求。

### 第 17 步：⑥ 合规映射
**文件**：`secassess/compliance/frameworks.py`（CIS Controls v8、ISO/IEC 27001:2022 附录 A 的控制项编号；等保 2.0 待 §15 确认后补充）、`secassess/compliance/mapper.py`、`secassess/agents/compliance.py`；报告增加合规矩阵；`tests/test_compliance.py`

**完成标准**：`python -m pytest tests/test_compliance.py -q` 返回 0，至少覆盖：
- 各类发现能映射到控制项。
- 矩阵中每个控制项的状态为"有未关闭问题 / 已覆盖无问题 / 无证据"。
- 误报和已接受风险不计为未关闭问题。
- 人工证据可以把控制项标为已覆盖。
- 报告输出合规矩阵。

## M3 · 治理与事实源（多源去重合并、证据链可追溯、权限门控）

### 第 18 步：L0 数据导入（② CMDB、④ 被动采集、⑤ 既有扫描结果）
**文件**：`secassess/inputs/cmdb.py`（CSV）、`secassess/inputs/passive.py`（DNS/流量记录 CSV）、`secassess/inputs/nessus.py`（.nessus XML，使用 defusedxml 或安全的标准库解析）、`tests/test_imports.py`

**完成标准**：`python -m pytest tests/test_imports.py -q` 返回 0，至少覆盖：
- CMDB 导入后，资产节点带上重要性分级和负责人。
- Nessus 导入的发现 channel 为 `import`，并与主动扫描的同一问题合并。
- 被动采集发现的新资产 channel 为 `passive`。
- 导入的 XML 中含 DOCTYPE/实体定义时被拒绝（防 XXE / 实体膨胀）。
- 授权范围外的导入记录被标记为 `out_of_scope`，不进入扫描目标。

### 第 19 步：风险评分模型
**文件**：`secassess/core/risk.py`、`secassess/inputs/threat_intel.py`（离线 KEV/EPSS JSON）、`tests/test_risk.py`

**完成标准**：`python -m pytest tests/test_risk.py -q` 返回 0，至少覆盖：
- 分数单调性：严重性越高、资产越重要、暴露在互联网、命中 KEV、EPSS 越高，分数都越高。
- 分数在 0–100 之间，并给出 P1–P4 优先级。
- 事实源写入发现时自动计算评分；报告按风险排序。

### 第 20 步：评估生命周期 + 复测闭环
**文件**：`secassess/core/lifecycle.py`、`tests/test_lifecycle.py`

**完成标准**：`python -m pytest tests/test_lifecycle.py -q` 返回 0，至少覆盖：
- 状态流转为 draft → scoped → active → review → reported → retest → closed，非法跳转被拒绝。
- 进入 active 前必须授权与凭证就绪。
- 复测时：覆盖了的目标上未再出现的发现标为已验证修复；再次出现的标为回归；未覆盖的目标保持原状态。

### 第 21 步：M3 的 API 与证据链查询
**文件**：`secassess/api/app.py`（imports、risk、lifecycle、compliance、`/findings/{id}/evidence`）、`tests/test_api_m3.py`

**完成标准**：`python -m pytest tests/test_api_m3.py -q` 返回 0，至少覆盖：
- 各端点的权限门控（导入需要 integrate 权限）。
- 证据链端点返回 通道 → 引擎 → 时间 → 原始证据（含 sha256 校验结果）→ 资产节点。

## M4 · 对标顶级升级（攻击路径 + choke-point、验证降误报、持续触发）

### 第 22 步：Exposure Graph 攻击路径与 choke point
**文件**：`secassess/core/exposure.py`、`tests/test_exposure.py`

**完成标准**：`python -m pytest tests/test_exposure.py -q` 返回 0，至少覆盖：
- 从入口到核心资产（crown jewel）的最短路径按边权重计算。
- choke point 排名正确（被最多路径经过的节点排在最前）。
- 没有路径时返回空结果；不存在的节点报错。
- 发现能自动生成 `exploitable_via` 边。

### 第 23 步：确定性可利用性验证器（§10.2）
**文件**：`secassess/core/validator.py`、`tests/test_validator.py`

**完成标准**：`python -m pytest tests/test_validator.py -q` 返回 0，至少覆盖：
- 验证器独立于 LLM；LLM 只能提交"假设"。
- 非侵入式检查（版本区间比对、服务可达性）基于事实源数据完成，不发网络请求。
- 侵入式验证必须先走 HITL。
- 验证成功时写回 `confidence=confirmed` 和 evidence_ref；验证不成立时不提升置信度。

### 第 24 步：CTEM 持续触发
**文件**：`secassess/core/ctem.py`、`tests/test_ctem.py`

**完成标准**：`python -m pytest tests/test_ctem.py -q` 返回 0，至少覆盖：
- 新资产、配置漂移、新情报命中、周期到期这四种触发条件都能产生重评估任务。
- 重评估同样经过 Scope Gate；同一资产在冷却期内不会重复触发。
- 调度器可以启动、停止，测试中时钟可注入。

## 阶段验收
- 第 3 节整体验收表中的所有命令仍然返回 0。
- `python demo.py` 增加演示 Copilot 自然语言评估和合规矩阵两段内容。
- 远端 CI 为绿色。

---

# 第三阶段：M5 企业化（不依赖外部基础设施的部分）

§15 已确认：部署形态＝客户本地/私有化；凭证托管＝自建 HashiCorp Vault；合规框架＝等保 2.0 + ISO 27001 + CIS。
本阶段只做**不依赖外部基础设施**的部分；需要 Redis/Celery、真实 SSO/SIEM/ITSM 服务的部分留作可替换抽象并记录。

- 第 25 步：等保 2.0 合规控制项映射（扩充 frameworks，合规矩阵三框架齐全）。
- 第 26 步：多租户数据隔离加固（缺口④）——Tenant 层覆盖 project，跨租户访问拒绝，全存储隔离测试。
- 第 27 步：整改闭环 / 工单（缺口⑨）——Ticket 抽象 + 本地后端，从发现开工单、回填整改状态；ITSM 连接器接口。
- 第 28 步：外部集成接口（缺口⑩）——SSO 认证提供方接口、SIEM 事件导出接口、ITSM 工单连接器接口；各带本地实现，不接真实服务。
- 第 29 步：平台可观测性（缺口⑫）——/metrics 端点与结构化事件计数。
- 第 30 步：内容更新流水线（缺口⑪）——版本固定的内容包（框架/模板版本）+ CIS MCP Benchmark 审查闸门占位。
- 第 31 步：自身过 CIS 基线自检（M5 出口）——对平台自身配置做基线自评（fail-closed 默认、无明文凭证、审计链、RBAC 等）。

**留作抽象/记录**：分布式扫描 worker（Redis + Celery/RQ，接口为 JobManager store）、真实 SSO/SIEM/ITSM 对接、Vault 生产部署。
