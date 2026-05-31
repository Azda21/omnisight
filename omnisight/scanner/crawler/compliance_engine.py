"""Legal & Compliance Engine - Automated legal rule enforcement.

Prevents scanning in restricted regions/organizations.
Enforces GDPR, CCPA, and local regulations.
Implements opt-out mechanisms and legal disclaimers.
"""

import logging
from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime
import json

logger = logging.getLogger("omnisight.scanner.crawler.compliance")


class LegalJurisdiction(Enum):
    """Geographic jurisdictions with different legal requirements."""
    US = "us"
    EU = "eu"  # GDPR
    CN = "cn"
    RU = "ru"
    IR = "ir"
    KP = "kp"  # North Korea
    OTHER = "other"


class ComplianceRule:
    """Single compliance rule."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        jurisdictions: List[LegalJurisdiction],
        action: str = "block",  # "block", "warn", "log", "report"
        severity: str = "high",  # "critical", "high", "medium", "low"
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.jurisdictions = jurisdictions
        self.action = action
        self.severity = severity

    def applies_to(self, jurisdiction: LegalJurisdiction) -> bool:
        """Check if rule applies to jurisdiction."""
        return jurisdiction in self.jurisdictions


class LegalComplianceEngine:
    """Central compliance engine."""

    def __init__(self):
        self.rules: Dict[str, ComplianceRule] = {}
        self._init_default_rules()
        self.violations: List[Dict[str, Any]] = []
        self.opt_out_list: set = set()  # IPs/CIDRs opted out from scanning

    def _init_default_rules(self) -> None:
        """Initialize default legal rules."""
        
        # GDPR - EU data protection
        self.add_rule(
            ComplianceRule(
                rule_id="gdpr_001",
                name="GDPR Data Protection",
                description="Personal data processing restricted by GDPR",
                jurisdictions=[LegalJurisdiction.EU],
                action="block",
                severity="critical",
            )
        )

        # CCPA - California privacy
        self.add_rule(
            ComplianceRule(
                rule_id="ccpa_001",
                name="CCPA California Privacy",
                description="Consumer privacy rights under CCPA",
                jurisdictions=[LegalJurisdiction.US],
                action="warn",
                severity="high",
            )
        )

        # Sanctioned countries
        for sanct_country in [LegalJurisdiction.IR, LegalJurisdiction.KP, LegalJurisdiction.RU]:
            self.add_rule(
                ComplianceRule(
                    rule_id=f"sanctions_{sanct_country.value}",
                    name=f"Sanctions - {sanct_country.value.upper()}",
                    description=f"Scanning restricted in {sanct_country.value}",
                    jurisdictions=[sanct_country],
                    action="block",
                    severity="critical",
                )
            )

        # Healthcare - HIPAA compliance
        self.add_rule(
            ComplianceRule(
                rule_id="hipaa_001",
                name="Healthcare Data - HIPAA",
                description="Protected health information restrictions",
                jurisdictions=[LegalJurisdiction.US],
                action="block",
                severity="critical",
            )
        )

        logger.info(f"Initialized {len(self.rules)} compliance rules")

    def add_rule(self, rule: ComplianceRule) -> None:
        """Add a compliance rule."""
        self.rules[rule.rule_id] = rule
        logger.debug(f"Added compliance rule: {rule.rule_id}")

    async def check_target(
        self, target: str, jurisdiction: Optional[LegalJurisdiction] = None
    ) -> Dict[str, Any]:
        """
        Check if target is legally compliant to scan.
        
        Returns:
            {
                "allowed": bool,
                "violations": [list of violated rules],
                "action": str (block/warn/report),
                "severity": str,
            }
        """
        if jurisdiction is None:
            jurisdiction = LegalJurisdiction.OTHER

        # Check opt-out list
        if target in self.opt_out_list:
            return {
                "allowed": False,
                "violations": ["target_opted_out"],
                "action": "block",
                "severity": "high",
            }

        violations = []
        max_severity = None

        for rule in self.rules.values():
            if rule.applies_to(jurisdiction):
                violations.append(
                    {
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "action": rule.action,
                        "severity": rule.severity,
                    }
                )
                if rule.action == "block":
                    max_severity = "critical"
                elif max_severity != "critical":
                    max_severity = rule.severity

        allowed = not any(v["action"] == "block" for v in violations)

        result = {
            "allowed": allowed,
            "violations": violations,
            "action": "block" if not allowed else "proceed",
            "severity": max_severity or "low",
            "jurisdiction": jurisdiction.value,
            "checked_at": datetime.now().isoformat(),
        }

        if not allowed:
            self.violations.append({"target": target, **result})

        return result

    def add_to_opt_out(self, target: str) -> None:
        """Add IP/CIDR to opt-out list."""
        self.opt_out_list.add(target)
        logger.info(f"Added {target} to opt-out list")

    def remove_from_opt_out(self, target: str) -> None:
        """Remove IP/CIDR from opt-out list."""
        self.opt_out_list.discard(target)
        logger.info(f"Removed {target} from opt-out list")

    def get_violations(self) -> List[Dict[str, Any]]:
        """Get all recorded violations."""
        return self.violations.copy()

    async def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance audit report."""
        return {
            "report_generated": datetime.now().isoformat(),
            "total_rules": len(self.rules),
            "total_violations": len(self.violations),
            "opted_out_targets": len(self.opt_out_list),
            "violations_by_severity": self._group_violations_by_severity(),
            "opt_out_list_sample": list(self.opt_out_list)[:10],
        }

    def _group_violations_by_severity(self) -> Dict[str, int]:
        """Group violations by severity."""
        groups = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for violation in self.violations:
            severity = violation.get("severity", "low")
            if severity in groups:
                groups[severity] += 1
        return groups

    async def export_opt_out_list(self, filepath: str) -> None:
        """Export opt-out list to file."""
        with open(filepath, "w") as f:
            json.dump(list(self.opt_out_list), f)
        logger.info(f"Exported opt-out list to {filepath}")

    async def import_opt_out_list(self, filepath: str) -> None:
        """Import opt-out list from file."""
        try:
            with open(filepath) as f:
                items = json.load(f)
                self.opt_out_list.update(items)
            logger.info(f"Imported {len(items)} items to opt-out list")
        except Exception as e:
            logger.error(f"Failed to import opt-out list: {e}")


class GDPRCompliance:
    """Specific GDPR compliance checks."""

    @staticmethod
    def is_personal_data(data: Dict[str, Any]) -> bool:
        """Check if data contains personal information."""
        personal_fields = {
            "email",
            "phone",
            "name",
            "ssn",
            "username",
            "user_id",
            "hostname",
            "mac_address",
        }
        return bool(personal_fields.intersection(data.keys()))

    @staticmethod
    def requires_consent(target: str, jurisdiction: str) -> bool:
        """Check if scanning requires consent."""
        return jurisdiction == "eu" or target.endswith(".eu")


class CCPACompliance:
    """Specific CCPA compliance checks."""

    @staticmethod
    def is_consumer_data(data: Dict[str, Any]) -> bool:
        """Check if data is consumer/California resident data."""
        sensitive_indicators = {
            "ssn",
            "drivers_license",
            "passport",
            "bank_account",
        }
        return bool(sensitive_indicators.intersection(data.keys()))

    @staticmethod
    def right_to_delete_applicable(target: str) -> bool:
        """Check if CCPA right-to-delete applies."""
        return target.endswith(".com") or target.endswith(".us")
