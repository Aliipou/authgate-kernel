"""
Anthropic tool-use adapter.

Intercepts Anthropic tool_use content blocks and verifies each tool call
against the Freedom Kernel before the tool function executes.

Usage:

    from authgate.adapters.anthropic import AnthropicKernelAdapter

    adapter = AnthropicKernelAdapter(
        verifier=verifier,
        agent=bot_entity,
        resource_map={
            "read_file":   ([], [file_resource]),      # (read, write)
            "write_report": ([file_resource], [report]),
        },
    )

    # After getting a response from client.messages.create(...)
    for block in response.content:
        if block.type == "tool_use":
            adapter.check_block(block)  # raises PermissionError if blocked
            result = your_tool_functions[block.name](**block.input)
            # feed result back as tool_result...
"""
from __future__ import annotations

from typing import Any

from authgate.kernel import Action, Entity, FreedomVerifier, Resource


class AnthropicKernelAdapter:
    """
    Kernel adapter for Anthropic tool-use responses.

    Verifies every tool_use content block before execution.
    """

    def __init__(
        self,
        verifier: FreedomVerifier,
        agent: Entity,
        resource_map: dict[str, tuple[list[Resource], list[Resource]]] | None = None,
    ) -> None:
        self.verifier = verifier
        self.agent = agent
        self.resource_map = resource_map or {}

    def check_block(self, block: Any) -> None:
        """
        Check an Anthropic ToolUseBlock before executing the tool.

        Raises PermissionError if the kernel blocks the action.

        Args:
            block: An object with .type == "tool_use", .id, .name attributes.
        """
        reads, writes = self.resource_map.get(block.name, ([], []))
        result = self.verifier.verify(
            Action(
                action_id=block.id,
                actor=self.agent,
                description=f"tool:{block.name}",
                resources_read=list(reads),
                resources_write=list(writes),
            )
        )
        if not result.permitted:
            raise PermissionError(result.summary())

    def check(
        self,
        action_id: str,
        tool_name: str,
        resources_read: list[Resource] | None = None,
        resources_write: list[Resource] | None = None,
        **flags: bool,
    ):
        """Verify a tool call manually (without a block object)."""
        return self.verifier.verify(
            Action(
                action_id=action_id,
                actor=self.agent,
                description=f"tool:{tool_name}",
                resources_read=resources_read or [],
                resources_write=resources_write or [],
                **flags,
            )
        )

    def tool_definitions(self) -> list[dict]:
        """Build Anthropic-format tool definitions from the resource map."""
        return [
            {
                "name": name,
                "description": f"Tool {name}",
                "input_schema": {
                    "type": "object",
                    "properties": {},
                },
            }
            for name in self.resource_map
        ]
