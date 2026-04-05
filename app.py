from flask import Flask, request, jsonify
import time
import re

app = Flask(__name__)

# --- Injection Detection ---
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

BLOCK_THRESHOLD = 2
MASK_THRESHOLD = 1

# --- Custom PII Patterns (replaces Presidio) ---
PII_PATTERNS = {
    "EMAIL": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    "PHONE": r'\b(\+92|0)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{7,8}\b',
    "API_KEY": r'\b[A-Za-z0-9]{32,45}\b',
    "CNIC": r'\b\d{5}-\d{7}-\d{1}\b',
    "IP_ADDRESS": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
}

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
    found = []
    for entity, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            found.append({"type": entity, "matches": matches})
    return found

def mask_pii(text):
    for entity, pattern in PII_PATTERNS.items():
        text = re.sub(pattern, f"[{entity}_REDACTED]", text)
    return text

def apply_policy(injection_score, pii_results, text):
    if injection_score >= BLOCK_THRESHOLD:
        return "BLOCK", text, "Injection attack detected"
    if pii_results:
        masked = mask_pii(text)
        return "MASK", masked, "PII detected and masked"
    if injection_score >= MASK_THRESHOLD:
        return "MASK", text, "Suspicious input flagged"
    return "ALLOW", text, "Input is safe"

@app.route("/analyze", methods=["POST"])
def analyze():
    start = time.time()
    data = request.get_json()
    user_input = data.get("text", "")

    injection_score, matched_keywords = check_injection(user_input)
    pii_results = check_pii(user_input)
    decision, output_text, reason = apply_policy(injection_score, pii_results, user_input)

    latency = round((time.time() - start) * 1000, 2)

    return jsonify({
        "decision": decision,
        "output": output_text,
        "reason": reason,
        "injection_score": injection_score,
        "matched_keywords": matched_keywords,
        "pii_found": [p["type"] for p in pii_results],
        "latency_ms": latency
    })

if __name__ == "__main__":
    app.run(debug=True)