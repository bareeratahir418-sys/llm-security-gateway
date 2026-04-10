import re
from presidio_analyzer import PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpArtifacts
from presidio_analyzer import EntityRecognizer, RecognizerResult

# CUSTOMIZATION 1: Custom Pattern Recognizers
def get_cnic_recognizer():
    cnic_pattern = Pattern(
        name="CNIC_PATTERN",
        regex=r"\b\d{5}-\d{7}-\d{1}\b",
        score=0.9
    )
    return PatternRecognizer(
        supported_entity="CNIC",
        patterns=[cnic_pattern],
        context=["cnic", "national", "identity", "card"]
    )

def get_phone_recognizer():
    phone_pattern = Pattern(
        name="PK_PHONE_PATTERN",
        regex=r"\b((\+92|0092|0)[-.\s]?)?(3\d{2})[-.\s]?\d{7}\b",
        score=0.85
    )
    return PatternRecognizer(
        supported_entity="PK_PHONE",
        patterns=[phone_pattern],
        context=["call", "phone", "mobile", "contact"]
    )

def get_api_key_recognizer():
    api_pattern = Pattern(
        name="API_KEY_PATTERN",
        regex=r"\b(sk-|pk-|api-|key-)[A-Za-z0-9]{20,45}\b",
        score=0.95
    )
    return PatternRecognizer(
        supported_entity="API_KEY",
        patterns=[api_pattern],
        context=["api", "key", "token", "secret"]
    )

# CUSTOMIZATION 2: Context-Aware Scoring
class ContextAwareEmailRecognizer(EntityRecognizer):
    CONTEXT_WORDS = ["email", "contact", "send", "mail", "reach"]
    EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

    def __init__(self):
        super().__init__(
            supported_entities=["EMAIL_ADDRESS"],
            name="ContextAwareEmailRecognizer"
        )

    def load(self):
        pass

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        context_boost = any(w in text.lower() for w in self.CONTEXT_WORDS)
        for match in self.EMAIL_REGEX.finditer(text):
            score = 0.75
            if context_boost:
                score = min(score + 0.15, 1.0)
            results.append(RecognizerResult(
                entity_type="EMAIL_ADDRESS",
                start=match.start(),
                end=match.end(),
                score=score
            ))
        return results

# CUSTOMIZATION 3: Composite Entity Detection
class CompositeIdentityRecognizer(EntityRecognizer):
    CNIC_RE  = re.compile(r"\b\d{5}-\d{7}-\d{1}\b")
    PHONE_RE = re.compile(r"\b((\+92|0)?3\d{2}[-.\s]?\d{7})\b")
    NAME_RE  = re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")

    def __init__(self):
        super().__init__(
            supported_entities=["COMPOSITE_IDENTITY"],
            name="CompositeIdentityRecognizer"
        )

    def load(self):
        pass

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        if self.NAME_RE.search(text) and (self.CNIC_RE.search(text) or self.PHONE_RE.search(text)):
            results.append(RecognizerResult(
                entity_type="COMPOSITE_IDENTITY",
                start=0,
                end=len(text),
                score=0.99
            ))
        return results
