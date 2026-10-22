"""测试用的最小 stdio MCP server（纯标准库，不产生网络流量）。

用法：python fake_mcp_server.py <mode>
mode: ok | tool_error | crash | slow
"""
import json
import sys
import time

MODE = sys.argv[1] if len(sys.argv) > 1 else "ok"


def send(message):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", **message}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    if method == "initialize":
        sys.stdout.write("not json noise\n")  # 客户端应忽略非协议输出
        send({"id": msg["id"], "result": {"protocolVersion": msg["params"]["protocolVersion"],
                                          "capabilities": {"tools": {}},
                                          "serverInfo": {"name": "fake", "version": "1"}}})
    elif method == "notifications/initialized":
        continue
    elif method == "tools/call":
        if MODE == "crash":
            sys.exit(3)
        if MODE == "slow":
            time.sleep(30)
        args = msg["params"]["arguments"]
        token = msg["params"].get("_meta", {}).get("progressToken")
        for i in (1, 2):
            send({"method": "notifications/progress",
                  "params": {"progressToken": token, "progress": i, "total": 2, "message": f"step {i}"}})
        if MODE == "tool_error":
            send({"id": msg["id"], "result": {"isError": True, "content": [{"type": "text", "text": "boom"}]}})
            continue
        findings = [{"target": f"{t}:443", "title": "SIM-MCP-001 placeholder", "severity": "medium",
                     "details": {"rule_id": "SIM-MCP-001", "port": 443,
                                 "credential_received": "credential" in args}} for t in args["targets"]]
        findings.append({"target": "203.0.113.99", "title": "out of scope", "severity": "high"})
        send({"id": msg["id"], "result": {"content": [{"type": "text", "text": json.dumps({"findings": findings})}]}})
