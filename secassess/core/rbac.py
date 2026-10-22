"""RBAC 职责分离（§8.1）与项目级数据隔离。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Role(str, enum.Enum):
    LEAD = "lead"          # 评估负责人
    ASSESSOR = "assessor"  # 评估员
    APPROVER = "approver"  # 审批人
    CLIENT = "client"      # 客户（只读）


class Permission(str, enum.Enum):
    VIEW = "view"
    SCAN = "scan"
    APPROVE = "approve"
    INTEGRATE = "integrate"  # 接入 / 凭证 / 授权范围
    REPORT = "report"


MATRIX: dict[Role, frozenset[Permission]] = {
    Role.LEAD: frozenset(Permission),
    Role.ASSESSOR: frozenset({Permission.VIEW, Permission.SCAN, Permission.REPORT}),
    Role.APPROVER: frozenset({Permission.VIEW, Permission.APPROVE}),
    Role.CLIENT: frozenset({Permission.VIEW}),
}


class PermissionDenied(PermissionError):
    pass


@dataclass(frozen=True)
class Principal:
    user: str
    role: Role
    projects: frozenset[str] = field(default_factory=lambda: frozenset({"*"}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", Role(self.role))
        object.__setattr__(self, "projects", frozenset(self.projects))

    def can_access(self, project_id: str) -> bool:
        return "*" in self.projects or project_id in self.projects

    def can(self, perm: Permission, project_id: str | None = None) -> bool:
        return perm in MATRIX[self.role] and (project_id is None or self.can_access(project_id))

    def require(self, perm: Permission, project_id: str | None = None) -> None:
        if not self.can(perm, project_id):
            where = f" @ {project_id}" if project_id else ""
            raise PermissionDenied(f"{self.user}({self.role.value}) 无 {perm.value} 权限{where}")
