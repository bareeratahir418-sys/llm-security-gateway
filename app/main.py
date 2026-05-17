from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from app.policy.policy_engine import PolicyEngine
from app.utils.language import check_language
from app.utils.logging import log_request, read_logs
import os
import time

app = FastAPI(title="LLM Security Gateway", version="2.0.0")
engine = PolicyEngine()

class PromptRequest(BaseModel):
    text: str
    input_id: str = "auto"

@app.get("/", response_class=HTMLResponse)
def root():
    html_path = os.path.join(os.getcwd(), 'index.html')
    if os.path.exists(html_path):
        with open(html_path, 'r', encoding='utf-8') as f:
            return f.read()
    return HTMLResponse("<h1>LLM Gateway Running</h1>")

@app.post("/analyze")
def analyze_prompt(request: PromptRequest):
    start_time = time.time()
    text = request.text.strip()
    input_id = request.input_id

    if not text:
        return JSONResponse({"error": "Empty prompt"})

    # Language detection
    lang_result = check_language(text)
    language = lang_result.get("detected", "en")

    # Run full evaluation
    result = engine.evaluate(text)

    latency_ms = round((time.time() - start_time) * 1000, 2)

    response = {
        "input_id": input_id,
        "language": language,
        "rule_score": result.get("rule_score", 0.0),
        "semantic_score": result.get("semantic_score", 0.0),
        "pii_entities": result.get("pii_entities", []),
        "final_risk": result.get("final_risk", 0.0),
        "decision": result.get("decision", "ALLOW"),
        "safe_text": result.get("safe_text", text),
        "reason_codes": result.get("reason_codes", []),
        "latency_ms": latency_ms
    }

    log_request(text, response)
    return JSONResponse(response)

@app.post("/evaluate")
def evaluate_prompt(request: PromptRequest):
    return analyze_prompt(request)

@app.get("/logs")
def get_logs():
    return JSONResponse(read_logs())

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}