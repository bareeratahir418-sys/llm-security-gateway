import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine


def _build_nlp_engine():
    try:
        cfg = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=cfg)
        return provider.create_engine()
    except Exception:
        return None


def _build_custom_recognizers():
    cnic_recognizer = PatternRecognizer(
        supported_entity="CNIC",
        patterns=[Pattern(
            name="cnic_pattern",
            regex=r'\b\d{5}-\d{7}-\d\b',
            score=0.95
        )],
        context=["cnic", "national id", "identity card", "nadra"]
    )

    student_id_recognizer = PatternRecognizer(
        supported_entity="STUDENT_ID",
        patterns=[Pattern(
            name="student_id_pattern",
            regex=r'\b[A-Z]{2}\d{2}[A-Z]{2,4}-\d{2,4}\b',
            score=0.95
        )],
        context=["student id", "registration", "reg no", "roll number"]
    )

    api_key_recognizer = PatternRecognizer(
        supported_entity="API_KEY",
        patterns=[Pattern(
            name="api_key_pattern",
            regex=r'\b(sk-[a-zA-Z0-9]{20,}|pk-[a-zA-Z0-9]{20,}|AIza[a-zA-Z0-9_\-]{35})\b',
            score=0.85
        )],
        context=["api key", "api_key", "secret key", "token", "bearer"]
    )

    pk_phone_recognizer = PatternRecognizer(
        supported_entity="PHONE_NUMBER",
        patterns=[Pattern(
            name="pk_phone_pattern",
            regex=r'\b0[3][0-9]{2}[-\s]?[0-9]{7}\b',
            score=0.9
        )],
        context=["contact", "phone", "call", "number", "mobile"]
    )

    return [cnic_recognizer, student_id_recognizer, api_key_recognizer, pk_phone_recognizer]


class PIIHandler:
    def __init__(self):
        nlp_engine = _build_nlp_engine()
        if nlp_engine:
            self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        else:
            self.analyzer = AnalyzerEngine()

        for recognizer in _build_custom_recognizers():
            self.analyzer.registry.add_recognizer(recognizer)

        self.anonymizer = AnonymizerEngine()

    def _analyze_raw(self, text: str):
        results = self.analyzer.analyze(text=text, language="en")
        results = [r for r in results if r.entity_type != "DATE_TIME"]

        name_pattern = re.search(
            r'\bmy name is\s+([A-Za-z]+)', text, re.IGNORECASE
        )
        if name_pattern:
            start = name_pattern.start(1)
            end = name_pattern.end(1)
            already = any(r.start <= start < r.end for r in results)
            if not already:
                results.append(RecognizerResult(
                    entity_type="PERSON",
                    start=start,
                    end=end,
                    score=0.9
                ))

        return results

    def analyze(self, text: str) -> list:
        results = self._analyze_raw(text)
        return [
            {
                "type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": round(r.score, 3),
                "text": text[r.start:r.end]
            }
            for r in results
        ]

    def anonymize(self, text: str) -> str:
        results = self._analyze_raw(text)
        if not results:
            return text
        anonymized = self.anonymizer.anonymize(
            text=text, analyzer_results=results
        )
        return anonymized.text