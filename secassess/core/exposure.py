"""Exposure Graph（§10.1）：在 Asset Graph 上计算攻击路径与 choke-point 优先修复清单。

依赖图中的关系边：reachable_to / exploitable_via / has_privilege / trusts（hosts 连接资产与其服务）。
漏洞发现可自动生成 exploitable_via 边（服务被利用即可危及其所在主机）。本模块只做图分析，不发流量。
"""
from __future__ import annotations

import heapq

from ..data.asset_graph import AssetGraph
from ..data.evidence import EvidenceStore
from ..models import Category, Severity

# 边权重：越容易利用，代价越低（攻击者更可能走）
EDGE_WEIGHTS = {"reachable_to": 1.0, "exploitable_via": 0.5, "has_privilege": 0.5, "trusts": 0.8, "hosts": 0.2}


def add_exploit_edges(graph: AssetGraph, evidence: EvidenceStore, project_id: str, *,
                      min_severity: Severity = Severity.HIGH) -> int:
    """为高危漏洞/配置发现在图中补 exploitable_via 边（service → 其宿主 asset）。返回新增边数。"""
    added = 0
    service_by_key = {n["key"]: n for n in graph.nodes(project_id, "service")}
    for f in evidence.query(project_id):
        if f.category not in (Category.VULNERABILITY, Category.MISCONFIG) or f.severity.rank < min_severity.rank:
            continue
        service = service_by_key.get(f.target.split("://")[-1])
        host_key = f.details.get("host") or f.target.split(":")[0].split("/")[0]
        if service is None:
            continue
        asset_id = graph.upsert_node(project_id, "asset", host_key)
        graph.add_edge(project_id, service["id"], asset_id, "exploitable_via",
                       {"via_finding": f.finding_id, "severity": f.severity.value})
        added += 1
    return added


def attack_paths(graph: AssetGraph, project_id: str, entries: list[str], crown_jewels: list[str], *,
                 max_paths: int = 20) -> list[dict]:
    """对每个 (entry, crown_jewel) 求加权最短路径（Dijkstra）。entries/crown_jewels 为节点 id。"""
    adjacency: dict[str, list[tuple[str, float, str]]] = {}
    for e in graph.edges(project_id):
        adjacency.setdefault(e["src"], []).append((e["dst"], EDGE_WEIGHTS.get(e["kind"], 1.0), e["kind"]))
    jewels = set(crown_jewels)
    paths = []
    for entry in entries:
        dist = {entry: 0.0}
        prev: dict[str, tuple[str, str]] = {}
        heap = [(0.0, entry)]
        while heap:
            d, node = heapq.heappop(heap)
            if d > dist.get(node, float("inf")):
                continue
            for nxt, weight, kind in adjacency.get(node, []):
                nd = d + weight
                if nd < dist.get(nxt, float("inf")):
                    dist[nxt], prev[nxt] = nd, (node, kind)
                    heapq.heappush(heap, (nd, nxt))
        for jewel in jewels:
            if jewel == entry or jewel not in dist:
                continue
            nodes, edges, cur = [jewel], [], jewel
            while cur != entry:
                cur, kind = prev[cur]
                nodes.append(cur)
                edges.append(kind)
            paths.append({"entry": entry, "target": jewel, "cost": round(dist[jewel], 3),
                          "nodes": nodes[::-1], "edges": edges[::-1]})
    paths.sort(key=lambda p: (p["cost"], p["entry"], p["target"]))
    return paths[:max_paths]


def choke_points(paths: list[dict]) -> list[dict]:
    """统计各中间节点被多少条攻击路径经过，按经过次数排序（最该优先修复的卡点在前）。"""
    counter: dict[str, int] = {}
    for p in paths:
        for node in p["nodes"][1:-1]:  # 不含入口与目标
            counter[node] = counter.get(node, 0) + 1
    total = len(paths) or 1
    ranked = [{"node": n, "paths": c, "score": round(c / total, 3)} for n, c in counter.items()]
    ranked.sort(key=lambda x: (-x["paths"], x["node"]))
    return ranked
