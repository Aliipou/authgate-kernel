"""
authgate-cli — command-line interface for authgate-kernel operations.

Commands:
  verify    Check whether an action JSON is permitted against a registry JSON
  audit     Audit log operations (verify chain integrity, replay entries)
  key       Key rotation management

Usage:
  authgate-cli verify --registry reg.json --action action.json [--audit log.jsonl]
  authgate-cli audit verify log.jsonl
  authgate-cli audit replay log.jsonl <index>
  authgate-cli audit stats log.jsonl
  authgate-cli key verify-cert cert.json

Exit codes:
  0 — operation completed successfully / action permitted
  1 — operation failed / action denied
  2 — usage or parse error
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load_json(path: str, label: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"error: {label} not found: {path}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"error: {label} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(2)


def _build_registry_from_dict(data: dict[str, Any]):
    from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
    from authgate.kernel.registry import OwnershipRegistry

    registry = OwnershipRegistry()
    agents: dict[str, Entity] = {}

    for a in data.get("agents", []):
        kind = AgentType[a["kind"].upper()]
        agents[a["id"]] = Entity(a["id"], kind)

    for m in data.get("machine_owners", []):
        machine = agents[m["machine"]]
        owner = agents[m["owner"]]
        registry.register_machine(machine, owner)

    resources: dict[str, Resource] = {}
    for r in data.get("resources", []):
        rtype = ResourceType[r["type"].upper()]
        res = Resource(
            name=r["id"],
            rtype=rtype,
            scope=r.get("scope", ""),
            is_public=r.get("is_public", False),
        )
        resources[r["id"]] = res

    for c in data.get("claims", []):
        holder = agents[c["holder"]]
        resource = resources[c["resource"]]
        claim = RightsClaim(
            holder=holder,
            resource=resource,
            can_read=c.get("can_read", True),
            can_write=c.get("can_write", False),
            can_delegate=c.get("can_delegate", False),
            confidence=float(c.get("confidence", 1.0)),
        )
        registry.add_claim(claim)

    return registry, agents, resources


def _build_action_from_dict(
    data: dict[str, Any],
    agents: dict,
    resources: dict,
):
    from authgate.kernel.entities import Entity, AgentType
    from authgate.kernel.verifier import Action

    actor_id = data["actor"]
    if actor_id not in agents:
        agents[actor_id] = Entity(actor_id, AgentType.MACHINE)
    actor = agents[actor_id]

    def resolve_resources(ids: list[str]) -> list:
        result = []
        for rid in ids:
            if rid in resources:
                result.append(resources[rid])
        return result

    return Action(
        action_id=data.get("action_id", "cli-action"),
        actor=actor,
        description=data.get("description", ""),
        resources_read=resolve_resources(data.get("resources_read", [])),
        resources_write=resolve_resources(data.get("resources_write", [])),
        resources_delegate=resolve_resources(data.get("resources_delegate", [])),
        increases_machine_sovereignty=data.get("increases_machine_sovereignty", False),
        resists_human_correction=data.get("resists_human_correction", False),
        bypasses_verifier=data.get("bypasses_verifier", False),
        weakens_verifier=data.get("weakens_verifier", False),
        disables_corrigibility=data.get("disables_corrigibility", False),
        machine_coalition_dominion=data.get("machine_coalition_dominion", False),
        coerces=data.get("coerces", False),
        deceives=data.get("deceives", False),
    )


def cmd_verify(args: argparse.Namespace) -> int:
    from authgate.kernel.audit import AuditLog
    from authgate.kernel.verifier import FreedomVerifier

    reg_data = _load_json(args.registry, "registry")
    action_data = _load_json(args.action, "action")

    registry, agents, resources = _build_registry_from_dict(reg_data)
    action = _build_action_from_dict(action_data, agents, resources)

    audit: AuditLog | None = None
    if args.audit:
        audit = AuditLog(path=args.audit)

    frozen = registry.freeze()
    verifier = FreedomVerifier(frozen, audit_log=audit)
    result = verifier.verify(action)

    output = {
        "action_id": result.action_id,
        "permitted": result.permitted,
        "confidence": result.confidence,
        "violations": list(result.violations),
        "warnings": list(result.warnings),
        "requires_human_arbitration": result.requires_human_arbitration,
    }
    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print(result.summary())

    return 0 if result.permitted else 1


def cmd_audit_verify(args: argparse.Namespace) -> int:
    from authgate.kernel.audit import AuditLog

    log, errors = AuditLog.load_and_verify(args.logfile)
    if errors:
        print(f"CHAIN BROKEN — {len(errors)} error(s):", file=sys.stderr)
        for e in errors[:10]:
            print(f"  {e}", file=sys.stderr)
        return 1
    print(f"OK — chain intact, {len(log)} entries")
    return 0


def cmd_audit_replay(args: argparse.Namespace) -> int:
    from authgate.kernel.audit import AuditLog

    log = AuditLog.load_from_file(args.logfile)
    try:
        entry = log.replay(args.index)
    except IndexError:
        print(f"error: index {args.index} out of range (log has {len(log)} entries)", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(entry, indent=2))
    return 0


def cmd_audit_stats(args: argparse.Namespace) -> int:
    from authgate.kernel.audit import AuditLog

    log, _ = AuditLog.load_and_verify(args.logfile)
    entries = log.entries()
    if not entries:
        print("empty log")
        return 0
    permitted = sum(1 for e in entries if e.get("permitted"))
    denied = len(entries) - permitted
    chain_ok = log.verify_chain()
    print(f"entries   : {len(entries)}")
    print(f"permitted : {permitted}")
    print(f"denied    : {denied}")
    print(f"chain     : {'OK' if chain_ok else 'BROKEN'}")
    print(f"head_hash : {log.head_hash()[:16]}...")
    return 0 if chain_ok else 1


def cmd_key_verify(args: argparse.Namespace) -> int:
    from authgate.key_rotation import RotationCertificate, verify_rotation

    cert_data = _load_json(args.cert, "certificate")
    try:
        cert = RotationCertificate.from_wire(cert_data)
    except (ValueError, KeyError) as e:
        print(f"error: invalid certificate format: {e}", file=sys.stderr)
        return 2

    print(f"Certificate version : {cert_data.get('version', '?')}")
    print(f"New epoch           : {cert.new_epoch}")
    print(f"Effective at        : {cert.effective_at}")
    print(f"Overlap window      : {cert.overlap_window_seconds}s")
    print(f"Old pubkey (hex)    : {cert.old_pubkey.hex()[:32]}...")
    print(f"New pubkey (hex)    : {cert.new_pubkey.hex()[:32]}...")
    print("note: signature verification requires --old-pubkey (not yet implemented in CLI)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authgate-cli",
        description="authgate-kernel CLI — capability verification, audit, and key management",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # verify
    p_verify = sub.add_parser("verify", help="Verify an action against a registry")
    p_verify.add_argument("--registry", required=True, metavar="REG.json",
                          help="Registry JSON file")
    p_verify.add_argument("--action", required=True, metavar="ACTION.json",
                          help="Action JSON file")
    p_verify.add_argument("--audit", metavar="LOG.jsonl",
                          help="Append audit entry to this JSONL file")
    p_verify.add_argument("--json", action="store_true",
                          help="Output machine-readable JSON instead of human text")
    p_verify.set_defaults(func=cmd_verify)

    # audit
    p_audit = sub.add_parser("audit", help="Audit log operations")
    audit_sub = p_audit.add_subparsers(dest="audit_command", required=True)

    p_av = audit_sub.add_parser("verify", help="Verify audit chain integrity")
    p_av.add_argument("logfile", metavar="LOG.jsonl")
    p_av.set_defaults(func=cmd_audit_verify)

    p_ar = audit_sub.add_parser("replay", help="Replay a single audit entry")
    p_ar.add_argument("logfile", metavar="LOG.jsonl")
    p_ar.add_argument("index", type=int, metavar="INDEX")
    p_ar.set_defaults(func=cmd_audit_replay)

    p_as = audit_sub.add_parser("stats", help="Show audit log statistics")
    p_as.add_argument("logfile", metavar="LOG.jsonl")
    p_as.set_defaults(func=cmd_audit_stats)

    # key
    p_key = sub.add_parser("key", help="Key rotation operations")
    key_sub = p_key.add_subparsers(dest="key_command", required=True)

    p_kv = key_sub.add_parser("verify-cert", help="Inspect a rotation certificate")
    p_kv.add_argument("cert", metavar="CERT.json")
    p_kv.set_defaults(func=cmd_key_verify)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
