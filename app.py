from flask import Flask, request, jsonify
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
import time

from recognizers import (
    get_cnic_recognizer,
    get_phone_recognizer,
    get_api_key_recognizer,
    ContextAwareEmailRecognizer,
    CompositeIdentityRecognizer
)

app = Flask(__name__)

# Setup Presidio with custom recognizers
registry = RecognizerRegistry()
registry.load_predefined_recognizers()
registry.add_recognizer(get_cnic_recognizer())
registry.add_recognizer(get_phone_recognizer())
registry.add_recognizer(get_api_key_recognizer())
registry.add_recognizer(ContextAwareEmailRecognizer())
registry.add_recognizer(CompositeIdentityRecognizer())

analyzer  = AnalyzerEngine(registry=registry)
anonymizer = AnonymizerEngine()

# Injection keywords
INJECTION_KEYWORDS = [
    "ignore previous instructions",
    "ignore all instructions",
    "you are now",
    "disregard",
    "forget your instructions",
    "jailbreak",
    "bypass",
    "pretend you are",
    "act as",
    "do anything now",
    "dan mode"
]

# Configurable thresholds
BLOCK_THRESHOLD = 2
MASK_THRESHOLD  = 1

def check_injection(text):
    text_lower = text.lower()
    score = 0
    matched = []
    for keyword in INJECTION_KEYWORDS:
        if keyword in text_lower:
            score += 1
            matched.append(keyword)
    return score, matched

def check_pii(text):
    results = analyzer.analyze(
        text=text,
        language="en",
        entities=[
            "EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON",
            "CNIC", "PK_PHONE", "API_KEY",
            "COMPOSITE_IDENTITY", "IP_ADDRESS", "CREDIT_CARD"
        ]
    )
    return results

def apply_policy(injection_score, pii_results, text):
    if injection_score >= BLOCK_THRESHOLD:
        return "BLOCK", text, "Injection attack detected"
    if pii_results:
        anonymized = anonymizer.anonymize(text=text, analyzer_results=pii_results)
        return "MASK", anonymized.text, "PII detected and masked"
    if injection_score >= MASK_THRESHOLD:
        return "MASK", text, "Suspicious input flagged"
    return "ALLOW", text, "Input is safe"

@app.route("/analyze", methods=["POST"])
def analyze():
    start = time.time()
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "Missing 'text' field"}), 400

    user_input = data.get("text", "")
    injection_score, matched_keywords = check_injection(user_input)
    pii_results = check_pii(user_input)
    decision, output_text, reason = apply_policy(injection_score, pii_results, user_input)
    latency = round((time.time() - start) * 1000, 2)

    return jsonify({
        "decision":         decision,
        "output":           output_text,
        "reason":           reason,
        "injection_score":  injection_score,
        "matched_keywords": matched_keywords,
        "pii_found":        list(set([r.entity_type for r in pii_results])),
        "latency_ms":       latency
    })

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "LLM Security Gateway is running"})

if __name__ == "__main__":
    app.run(debug=True)
