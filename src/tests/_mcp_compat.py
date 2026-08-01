"""Building an MCP server the same way on SDK 1.x and 2.x.

The package supports both, so the tests that drive a real server have to run on both. The
two differ in the server class, in how transport options are passed, and in which protocol
version they call latest — but they share the handshake protocol versions, so the tests pin
one of those and keep a single wire path.
"""

from __future__ import annotations

from typing import Any, Callable

#: A handshake version both generations support. Deliberately not "latest": on 2.x that is
#: the modern protocol, whose per-request `_meta` envelope and mirrored `mcp-method` headers
#: are a second wire dialect the identity tests have no reason to exercise. It is also the
#: dangerous path on 1.x — handshake versions are what dispatch through the long-lived
#: session task.
PROTOCOL_VERSION = "2025-11-25"


def sdk_major() -> int:
    from importlib.metadata import version

    return int(version("mcp").split(".", 1)[0])


IS_V1 = sdk_major() < 2


def build_server(name: str, *, server_middleware: list[Any] | None = None) -> Any:
    """An MCP server object with a `.tool(name=...)` registration decorator."""
    if IS_V1:
        from mcp.server.fastmcp import FastMCP

        # 1.x has no context-tier middleware; per-handler `@guarded` is the only seam.
        return FastMCP(name)

    from mcp.server.mcpserver import MCPServer

    return MCPServer(name, middleware=server_middleware or [])


def register_tool(server: Any, name: str, fn: Callable[..., Any]) -> None:
    server.tool(name=name)(fn)


def build_app(server: Any, *, stateless: bool, path: str = "/mcp") -> Any:
    """The streamable-HTTP ASGI app, with DNS-rebinding protection off.

    That protection rejects the synthetic Host `ASGITransport` sends and is irrelevant to
    anything these tests assert.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    security = TransportSecuritySettings(enable_dns_rebinding_protection=False)

    if IS_V1:
        server.settings.streamable_http_path = path
        server.settings.json_response = True
        server.settings.stateless_http = stateless
        server.settings.transport_security = security
        return server.streamable_http_app()

    return server.streamable_http_app(
        streamable_http_path=path,
        json_response=True,
        stateless_http=stateless,
        transport_security=security,
    )
