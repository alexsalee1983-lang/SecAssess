# SecAssess

面向**授权范围内**的防御性安全评估工具箱：资产测绘 → 漏洞扫描 → 配置基线，在同一事实源中贯通并出报告。
架构见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，分步计划与完成标准见 [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)。

当前进度：**M0–M4 完成；M5 完成不依赖外部基础设施的部分**（多租户隔离、整改工单、SSO/SIEM/ITSM
接口、可观测性、内容更新流水线、平台基线自检）。§15 已确认：部署＝客户本地/私有化、凭证＝自建
HashiCorp Vault、合规＝等保 2.0 + ISO 27001 + CIS。**留待对接基础设施**：分布式扫描 worker
（Redis + Celery/RQ）、真实 SSO/SIEM/ITSM 服务、Vault 生产部署。扫描引擎目前是 mock 适配器（合成占位结果，无网络流量）
加一个通用 MCP 适配器，真实引擎通过 MCP server 在运行时接入。

## 快速上手

```bash
pip install -e ".[dev,api,docx]"     # 核心零依赖；dev=pytest/ruff，api=fastapi/uvicorn/httpx，docx=python-docx
python -m pytest tests -q            # 单元测试
python demo.py                       # 端到端演示，报告写到 reports_out/
python -m secassess serve --config examples/platform.json   # 启动整套系统；浏览器打开 http://127.0.0.1:8000/ 即控制台
bash scripts/smoke_api.sh            # API 冒烟测试（自动启停服务）
```

`examples/platform.json` 里的 API Key 仅供演示，部署前务必替换。设置环境变量 `SECASSESS_SECRET`
可让 scope_token 的签名密钥在重启后保持不变。

## 架构落地对照

| 架构要求 | 实现 |
|---|---|
| §6 核心契约 | `secassess/models.py`：`ScanRequest`（无令牌、明文凭证、可注入目标一律拒绝）、`NormalizedFinding`（指纹去重） |
| 红线① 适配器隔离 | `adapters/base.py` 抽象接口 + `AdapterRegistry`；Agent 只依赖接口 |
| A 方案 MCP 接入 | `adapters/mcp.py`：stdio JSON-RPC 客户端，进度回传，越界结果丢弃，原始输出存为证据 |
| 红线② 授权前置（fail-closed） | `core/scope_gate.py`：白名单 + 免扫清单优先 + 有效期 + RoE；任一目标越界整体拒绝；HMAC 限时令牌绑定项目/类型/目标 |
| §8.2 HITL | `core/hitl.py`：deep/侵入式/对外/脆弱资产/窗口外/超速率/高权限凭证转审批；职责分离、动作指纹一致、一次性兑现 |
| §8.1 RBAC | `core/rbac.py`：4 角色 × 5 权限，项目隔离 |
| 横切② 审计 | `core/audit.py`：哈希链防篡改 |
| 红线③ 单一事实源 | `data/evidence.py`（多源合并、复核状态保留、证据内容寻址）+ `data/asset_graph.py` + `data/facts.py` |
| §11 非阻塞 | `core/jobs.py`：提交即返回、信号量并发、取消/超时、错误隔离、SSE |
| L3 Agent | `agents/`：资产 / 漏洞 / 基线 |
| L2 编排 | `core/orchestrator.py`：RBAC → L0 就绪 → Agent → Gate → 提交，全程审计；审批后 resume；主干流水线 |
| L6 输出 | `reports/engine.py`：Markdown / HTML / DOCX，含证据链 |
| API | `api/app.py`：REST + SSE，`X-API-Key` 认证 |

## 接入大模型规划器（DeepSeek 等国产模型）

Copilot 的规划器默认是确定性的规则规划器；也可接入 OpenAI 兼容的国产大模型（DeepSeek / 通义千问 /
Kimi / 智谱 GLM）。模型只负责**提议**步骤，所有提议仍须经白名单、种子范围校验、Scope Gate 与 HITL，
模型拿不到也无法伪造 scope_token / approval_id；调用失败或无 Key 时自动回退到规则规划器。

```bash
export DEEPSEEK_API_KEY=sk-...                     # 或 DASHSCOPE_API_KEY / MOONSHOT_API_KEY / ZHIPUAI_API_KEY
python scripts/deepseek_smoke.py --provider deepseek   # 实连冒烟（无 Key 时自动跳过）
```

平台配置里打开（见 `examples/platform_llm.json`）：

```json
{"llm_planner": {"provider": "deepseek"}}
```

`provider` 可选 `deepseek` / `qwen` / `moonshot` / `zhipu`，也可自定义 `base_url` 与 `model`。
API Key 从对应环境变量读取，不写入日志、发现或提示词。

## 接入真实引擎（MCP）

把 MCP server 写进平台配置的 `mcp_adapters`（样例见 `examples/mcp_adapters.json`）：

```json
{"name": "vuln-mcp", "command": ["python3", "-m", "your_vuln_mcp_server"], "tool_name": "scan",
 "scan_types": ["vuln"], "intrusive_level": "safe", "needs_credential": false}
```

工具会收到 `{"targets", "options", "rate_limit", "credential"?}` 参数，应返回
`{"findings": [{"target", "title", "severity", "category"?, "confidence"?, "details"?}]}`。
可用的真实引擎优先于 mock。凭证从 Vault 解析后传给工具，不会写入发现或日志。

## API 一览

| 方法 | 路径 | 说明 | 权限 |
|---|---|---|---|
| PUT/GET | `/projects/{pid}/scope` | 授权与交战规则 | integrate / view |
| POST | `/projects/{pid}/credentials` | 录入凭证，返回 `vault://` 引用 | integrate |
| POST | `/scans` | 提交扫描：202 + job_id，或 202 + approval_id，越界返回 403 | scan |
| GET | `/scans/{id}`、`/results`、`/stream` | 轮询 / 结果 / SSE | view |
| POST | `/scans/{id}/cancel` | 取消 | scan |
| GET/POST | `/approvals`、`/{id}/approve`、`/reject`、`/resume` | HITL 审批 | view / approve / scan |
| POST/GET | `/pipelines`、`/pipelines/{id}?wait=秒` | 主干流水线，支持长轮询 | scan / view |
| GET/PATCH | `/findings` | 查询 / 人工复核（high 及以上的风险接受需要 approve 权限） | view / scan |
| POST/GET | `/copilot/runs`、`/copilot/runs/{id}`、`/continue`、`/copilot/ask` | 自然语言评估回路与结果问答 | scan / view |
| POST | `/projects/{pid}/imports/{cmdb\|passive\|nessus}` | L0 数据导入（范围外跳过） | integrate |
| POST/GET | `/assessments`、`/{id}/transition`、`/{id}/retest` | 评估生命周期与复测闭环 | scan / view |
| GET | `/compliance/{pid}` | 合规覆盖矩阵 | view |
| POST | `/exposure/{pid}` | 攻击路径 + choke-point | view |
| POST | `/findings/{id}/validate` | 确定性可利用性验证（侵入式需审批） | scan |
| GET | `/findings/{id}/evidence` | 证据链 + 原始证据完整性校验 | view |
| POST/GET/PATCH | `/findings/{id}/ticket`、`/tickets`、`/tickets/{id}` | 整改工单（开单/列表/状态流转） | scan / view / scan |
| GET | `/siem/{pid}/events` | SIEM 事件导出（发现 + 审计） | view |
| GET | `/metrics`、`/content`、`/selfcheck` | 平台指标 / 内容包 / 基线自检 | view |
| GET | `/assets`、`/reports/{pid}?format=md\|html\|docx`、`/audit` | 资产 / 报告（含合规矩阵）/ 审计 | view / report / view |

## 使用边界

本工具只用于已获书面授权的评估。所有主动动作都必须通过 Scope Gate，无令牌不执行；
示例与测试只使用 RFC 5737 文档网段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）和 example.com。
