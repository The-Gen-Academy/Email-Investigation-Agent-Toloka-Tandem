"""Tendem MCP adapter. Tool inputs are checked against live schemas."""

import asyncio
from datetime import timedelta

import httpx
import jsonschema
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


class TendemClient:
    def __init__(self, api_key: str, url: str):
        self.api_key = api_key
        self.url = url

    async def _request(self, tool: str | None, arguments: dict):
        async with httpx.AsyncClient(
            headers={"Authorization": f"ApiKey {self.api_key}"},
            timeout=httpx.Timeout(30, read=65),
        ) as http:
            async with streamable_http_client(self.url, http_client=http) as (
                reader,
                writer,
                _,
            ):
                async with ClientSession(
                    reader, writer, read_timeout_seconds=timedelta(seconds=60)
                ) as session:
                    await session.initialize()
                    definitions = {
                        t.name: t for t in (await session.list_tools()).tools
                    }
                    if tool is None:
                        return sorted(definitions)
                    if tool not in definitions:
                        raise ValueError(f"Tendem no longer advertises {tool}")
                    jsonschema.validate(arguments, definitions[tool].inputSchema)
                    result = await session.call_tool(tool, arguments)
                    if result.isError:
                        text = " ".join(
                            p.text
                            for p in result.content
                            if getattr(p, "type", "") == "text"
                        )
                        raise RuntimeError(f"Tendem {tool}: {text[:1200]}")
                    if not isinstance(result.structuredContent, dict):
                        raise ValueError(
                            f"Tendem {tool} returned no structured response"
                        )
                    if definitions[tool].outputSchema:
                        jsonschema.validate(
                            result.structuredContent, definitions[tool].outputSchema
                        )
                    return result.structuredContent

    def call(self, tool: str, arguments: dict | None = None) -> dict:
        return asyncio.run(self._request(tool, arguments or {}))

    def tools(self) -> list[str]:
        return asyncio.run(self._request(None, {}))
