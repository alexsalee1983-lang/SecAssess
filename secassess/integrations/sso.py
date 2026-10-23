"""SSO 认证提供方接口（缺口⑩）：把外部身份凭据解析为平台 Principal。

本地实现 ApiKeyProvider 复用现有 X-API-Key 映射。对接 OIDC / SAML 时实现 AuthProvider.resolve 即可，
RBAC 与多租户隔离保持不变（解析结果仍是带 role/projects/tenant 的 Principal）。
"""
from __future__ import annotations

import abc

from ..core.rbac import Principal
from ..core.tenancy import DEFAULT_TENANT


class AuthError(PermissionError):
    pass


class AuthProvider(abc.ABC):
    @abc.abstractmethod
    def resolve(self, credential: str | None) -> Principal:
        """把凭据（API Key / Bearer token / 断言）解析为 Principal；失败抛 AuthError。"""


class ApiKeyProvider(AuthProvider):
    def __init__(self, api_keys: dict[str, Principal]) -> None:
        self._api_keys = api_keys

    def resolve(self, credential: str | None) -> Principal:
        principal = self._api_keys.get(credential or "")
        if principal is None:
            raise AuthError("缺少或无效的 API Key")
        return principal


class MappingOIDCProvider(AuthProvider):
    """OIDC 提供方的离线占位：按已验证的 subject 查映射（真实部署需先验证 JWT 签名/颁发方）。

    claims_verifier 由外部注入（负责校验 JWT 并返回 claims dict）；此处只做 claims → Principal 的映射，
    不自行信任未经验证的 token。未注入校验器时拒绝一切 token（fail-closed）。
    """

    def __init__(self, subject_map: dict[str, dict], claims_verifier=None) -> None:
        self._subjects = subject_map        # sub -> {user, role, projects, tenant}
        self._verify = claims_verifier

    def resolve(self, credential: str | None) -> Principal:
        if not credential or self._verify is None:
            raise AuthError("OIDC 校验器未配置或缺少 token（fail-closed）")
        claims = self._verify(credential)
        sub = claims.get("sub") if isinstance(claims, dict) else None
        mapping = self._subjects.get(sub or "")
        if mapping is None:
            raise AuthError(f"主体未授权: {sub}")
        return Principal(mapping["user"], mapping["role"], frozenset(mapping.get("projects", ["*"])),
                         mapping.get("tenant", DEFAULT_TENANT))
