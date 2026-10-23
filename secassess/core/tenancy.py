"""多租户数据隔离（缺口④）。

每个 project 归属一个 tenant；principal 也归属一个 tenant。跨租户访问一律拒绝——
即使 principal 的 projects 是通配 "*"，也只在本租户内有效，不能越到别的租户的项目。
数据层本就按 project_id 隔离，本模块在其上再加一层租户硬隔离。
"""
from __future__ import annotations

from .rbac import PermissionDenied, Principal

DEFAULT_TENANT = "default"


class TenantRegistry:
    def __init__(self) -> None:
        self._project_tenant: dict[str, str] = {}

    def set_project_tenant(self, project_id: str, tenant_id: str) -> None:
        self._project_tenant[project_id] = tenant_id or DEFAULT_TENANT

    def is_registered(self, project_id: str) -> bool:
        return project_id in self._project_tenant

    def tenant_of(self, project_id: str) -> str:
        return self._project_tenant.get(project_id, DEFAULT_TENANT)

    def visible_projects(self, tenant_id: str) -> list[str]:
        return [p for p, t in self._project_tenant.items() if t == tenant_id]

    def can_access(self, principal: Principal, project_id: str) -> bool:
        return self.tenant_of(project_id) == principal.tenant

    def require_access(self, principal: Principal, project_id: str) -> None:
        if not self.can_access(principal, project_id):
            raise PermissionDenied(
                f"{principal.user}(tenant={principal.tenant}) 不能访问其他租户的项目 {project_id}")
