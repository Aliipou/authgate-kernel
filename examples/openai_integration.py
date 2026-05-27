"""
OpenAI Agents + Freedom Kernel integration example.

Demonstrates how to gate every tool call through the kernel before execution.
No OpenAI API key required to run this example — it shows the gating logic.

For production use with the real OpenAI Agents SDK:
    pip install openai

Run:
    python examples/openai_integration.py
"""
from authgate import (
    AgentType,
    Entity,
    FreedomVerifier,
    OwnershipRegistry,
    Resource,
    ResourceType,
    RightsClaim,
)
from authgate.adapters.openai_agents import OpenAIKernelMiddleware

# ── Setup ─────────────────────────────────────────────────────────────────────

alice = Entity("Alice", AgentType.HUMAN)
bot = Entity("CodingAgent", AgentType.MACHINE)

codebase = Resource("codebase", ResourceType.FILE, scope="/repos/alice/")
prod_db = Resource("prod-db", ResourceType.DATABASE_TABLE, scope="/db/prod/")
scratch = Resource("scratch", ResourceType.FILE, scope="/tmp/agent/")

registry = OwnershipRegistry()
registry.register_machine(bot, alice)
registry.add_claim(RightsClaim(alice, codebase, can_read=True, can_delegate=True))
registry.add_claim(RightsClaim(alice, scratch, can_read=True, can_write=True, can_delegate=True))
registry.delegate(RightsClaim(bot, codebase, can_read=True), delegated_by=alice)
registry.delegate(RightsClaim(bot, scratch, can_read=True, can_write=True), delegated_by=alice)
# prod_db is NOT delegated to bot

verifier = FreedomVerifier(registry)
middleware = OpenAIKernelMiddleware(verifier, agent=bot)


# ── Tool definitions ──────────────────────────────────────────────────────────

@middleware.tool(resources_read=[codebase])
def read_file(path: str) -> str:
    """Read a file from the codebase."""
    return f"<contents of {path}>"


@middleware.tool(resources_write=[scratch])
def write_scratch(content: str) -> str:
    """Write content to the agent's scratch space."""
    return "written to scratch"


@middleware.tool(resources_write=[prod_db])
def write_production_db(query: str) -> str:
    """Execute a write query against the production database."""
    return "executed"  # This will never execute — kernel blocks it


# ── Demo ──────────────────────────────────────────────────────────────────────

print("=" * 60)
print("OpenAI Agents + Freedom Kernel")
print("=" * 60)

# Permitted: read codebase
print("\n1. read_file('main.py')")
try:
    result = read_file("main.py")
    print(f"   → {result}")
except PermissionError as e:
    print(f"   BLOCKED: {e}")

# Permitted: write scratch
print("\n2. write_scratch('analysis complete')")
try:
    result = write_scratch("analysis complete")
    print(f"   → {result}")
except PermissionError as e:
    print(f"   BLOCKED: {e}")

# Blocked: write prod DB — bot has no claim
print("\n3. write_production_db('DELETE FROM users') [no delegation]")
try:
    result = write_production_db("DELETE FROM users")
    print(f"   → {result}")
except PermissionError as e:
    print(f"   BLOCKED:\n   {str(e)[:200]}")

# Manual check — for when you have an OpenAI tool_call object
print("\n4. Manual check (simulating OpenAI tool_call object)")
result = middleware.check(
    action_id="call-001",
    tool_name="read_file",
    resources_read=[codebase],
)
print(f"   permitted={result.permitted}, confidence={result.confidence:.2f}")

print("\n5. Generate OpenAI tool definitions")
defs = middleware.openai_tool_definitions([read_file, write_scratch])
for d in defs:
    print(f"   {d['function']['name']}: {d['type']}")
