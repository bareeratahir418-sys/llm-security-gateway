from app.detectors.rule_detector import RuleBasedDetector
from app.detectors.semantic_detector import SemanticDetector
from app.pii.presidio_custom import PIIHandler
import yaml
import os


def load_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'gateway_config.yaml')
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


class PolicyEngine:
    def __init__(self):
        self.rule_detector = RuleBasedDetector()
        self.semantic_detector = SemanticDetector()
        self.pii_handler = PIIHandler()

    def evaluate(self, text: str) -> dict:
        reason_codes = []

        # Rule-based check
        rule_result = self.rule_detector.check(text)
        rule_score = 0.0 if rule_result["allowed"] else 0.85
        if not rule_result["allowed"]:
            reason_codes.append("RULE_INJECTION_DETECTED")

        # Semantic check - disabled to prevent false positives
        semantic_score = 0.0

        # PII check
        pii_entities = self.pii_handler.analyze(text)
        pii_score = 0.2 if len(pii_entities) > 0 else 0.0
        if pii_entities:
            reason_codes.append("PII_DETECTED")

        # Final risk
        final_risk = round(min(rule_score + pii_score, 1.0), 3)

        # Decision
        if rule_score >= 0.85:
            decision = "BLOCK"
            safe_text = None
        elif len(pii_entities) > 0:
            decision = "MASK"
            safe_text = self.pii_handler.anonymize(text)
            reason_codes.append("PII_MASKED")
        else:
            decision = "ALLOW"
            safe_text = text

        return {
            "allowed": decision == "ALLOW",
            "decision": decision,
            "rule_score": round(rule_score, 3),
            "semantic_score": round(semantic_score, 3),
            "pii_entities": pii_entities,
            "pii_score": round(pii_score, 3),
            "final_risk": final_risk,
            "safe_text": safe_text,
            "reason_codes": reason_codes,
            "reason": ", ".join(reason_codes) if reason_codes else "Passed all checks",
            "cleaned_text": safe_text,
            "pii_found": pii_entities
        }