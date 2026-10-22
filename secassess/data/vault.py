"""凭证引用解析（L0 ③）：业务层只传 vault:// 引用，使用时才解析，明文不进日志/发现/存储。

- vault://mem/<name>      进程内（测试、演示）
- vault://env/<VAR>       环境变量
- vault://kv/<mount>/<path>#<key>  HashiCorp Vault KV v2（需 VAULT_ADDR / VAULT_TOKEN）
"""
from __future__ import annotations

import json
import os
import urllib.request


class VaultError(LookupError):
    pass


class Secret:
    """包装明文，打印/格式化时一律脱敏，只有 reveal() 返回明文。"""
    __slots__ = ("ref", "_value")

    def __init__(self, ref: str, value: str) -> None:
        self.ref, self._value = ref, value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"Secret({self.ref}, ****)"

    __str__ = __repr__


class Vault:
    def __init__(self) -> None:
        self._mem: dict[str, str] = {}

    def put(self, name: str, value: str) -> str:
        if not name or "/" in name:
            raise VaultError("名称不能为空或包含 /")
        self._mem[name] = value
        return f"vault://mem/{name}"

    def exists(self, ref: str) -> bool:
        try:
            self.resolve(ref)
        except VaultError:
            return False
        return True

    def resolve(self, ref: str) -> Secret:
        if not isinstance(ref, str) or not ref.startswith("vault://"):
            raise VaultError("不是 vault:// 引用")
        backend, _, path = ref[len("vault://"):].partition("/")
        if backend == "mem" and path in self._mem:
            return Secret(ref, self._mem[path])
        if backend == "env" and path in os.environ:
            return Secret(ref, os.environ[path])
        if backend == "kv" and path:
            return Secret(ref, self._read_kv(path))
        raise VaultError(f"凭证不存在: {ref}")

    @staticmethod
    def _read_kv(path: str) -> str:
        addr, token = os.environ.get("VAULT_ADDR"), os.environ.get("VAULT_TOKEN")
        if not addr or not token:
            raise VaultError("未配置 VAULT_ADDR / VAULT_TOKEN")
        location, _, key = path.partition("#")
        mount, _, sub = location.partition("/")
        if not (mount and sub and key):
            raise VaultError("kv 引用格式应为 vault://kv/<mount>/<path>#<key>")
        req = urllib.request.Request(f"{addr.rstrip('/')}/v1/{mount}/data/{sub}", headers={"X-Vault-Token": token})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - 地址来自运维配置
                data = json.load(resp)["data"]["data"]
        except Exception as exc:  # 不回显响应内容，避免泄露
            raise VaultError(f"Vault 读取失败: {type(exc).__name__}") from None
        if key not in data:
            raise VaultError(f"Vault 路径缺少键: {key}")
        return str(data[key])
