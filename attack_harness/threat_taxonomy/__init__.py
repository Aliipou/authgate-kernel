"""
Threat taxonomy for authgate-kernel — Phase 0, O3 (ultimate-plan.md).

Modules:
  ontology            — adversarial ontology: attack class hierarchy and severity model
  authority_escalation — authority escalation tree: 6 escalation paths, kernel response assertions
  delegation_abuse    — delegation abuse catalog: orphaned/amplified/circular delegation attacks
  coercion_primitives — coercion primitives catalog: 10 sovereignty flags mapped to coercion types
"""
from .ontology import AttackClass, AttackSeverity, ThreatVector, AttackScenario

__all__ = ["AttackClass", "AttackSeverity", "ThreatVector", "AttackScenario"]
