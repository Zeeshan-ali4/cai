"""Metasploit RPC tool for CAI agents."""
from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Any
import msgpack
import requests
from cai.sdk.agents import function_tool


@dataclass
class MsfRpcConfig:
    url: str
    user: str
    password: str
    timeout: float = 30.0

    @classmethod
    def from_env(cls) -> "MsfRpcConfig":
        url = os.getenv("MSF_RPC_URL", "http://127.0.0.1:55553/api/")
        user = os.getenv("MSF_RPC_USER", "msf")
        password = os.getenv("MSF_RPC_PASS", "")
        timeout = float(os.getenv("MSF_RPC_TIMEOUT", "30"))
        return cls(url=url, user=user, password=password, timeout=timeout)


def _decode(obj: Any) -> Any:
    """Recursively decode bytes keys/values to strings."""
    if isinstance(obj, bytes):
        return obj.decode()
    if isinstance(obj, dict):
        return {_decode(k): _decode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decode(i) for i in obj]
    return obj


class MsfRpcClient:
    def __init__(self, config: MsfRpcConfig) -> None:
        self.config = config
        self._token: str | None = None

    def _post(self, payload: list) -> Any:
        response = requests.post(
            self.config.url,
            data=msgpack.packb(payload, use_bin_type=True),
            headers={"Content-Type": "binary/message-pack"},
            timeout=self.config.timeout,
        )
        response.raise_for_status()
        return _decode(msgpack.unpackb(response.content, raw=False))

    def login(self) -> str:
        result = self._post(["auth.login", self.config.user, self.config.password])
        token = result.get("token")
        if not token:
            raise ValueError(f"Metasploit RPC login failed: {result}")
        self._token = token
        return token

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        if not self._token:
            self.login()
        payload = [method, self._token]
        if params:
            payload.extend(params)
        return self._post(payload)


@function_tool
def msf_rpc_call(method: str, params: list[Any] | None = None) -> Any:
    """Call Metasploit RPC with a method and parameters.

    Args:
        method: The Metasploit RPC method (e.g., "module.search", "core.version").
        params: Optional list of parameters for the RPC method.
    """
    client = MsfRpcClient(MsfRpcConfig.from_env())
    return client.call(method, params)
