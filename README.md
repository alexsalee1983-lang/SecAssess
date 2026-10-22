# SecAssess

面向**授权范围内**的防御性安全评估工具箱：资产测绘 → 漏洞扫描 → 配置基线，在同一事实源中贯通并出报告。
架构见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，分步计划与完成标准见 [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)。

当前进度：**M0（异步内核与契约）+ M1（主干三件套）**。扫描引擎目前是 mock 适配器（合成占位结果，无网络流量）
加一个通用 MCP 适配器，真实引擎通过 MCP server 在运行时接入。

## 快速上手

```bash
pip install -e ".[dev,api,docx]"     # 核心零依赖；dev=pytest/ruff，api=fastapi/uvicorn/httpx，docx=python-docx
python -m pytest tests -q            # 单元测试
python demo.py                       # 端到端演示，报告写到 reports_out/
python -m secassess serve --config examples/platform.json   # 启动 API（默认 127.0.0.1:8000）
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
| GET | `/assets`、`/reports/{pid}?format=md\|html\|docx`、`/audit` | 资产 / 报告 / 审计 | view / report / view |

## 使用边界

本工具只用于已获书面授权的评估。所有主动动作都必须通过 Scope Gate，无令牌不执行；
示例与测试只使用 RFC 5737 文档网段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）和 example.com。
