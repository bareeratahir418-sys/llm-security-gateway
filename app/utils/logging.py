import os
import json
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'gateway.log')


def log_request(prompt: str, result: dict):
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        entry = {
            "timestamp": datetime.now().isoformat(),
            "input_id": result.get("input_id", "auto"),
            "prompt_preview": prompt[:120],
            "language": result.get("language", "unknown"),
            "rule_score": result.get("rule_score", 0.0),
            "semantic_score": result.get("semantic_score", 0.0),
            "final_risk": result.get("final_risk", 0.0),
            "decision": result.get("decision", "ALLOW"),
            "reason_codes": result.get("reason_codes", []),
            "pii_count": len(result.get("pii_entities", [])),
            "pii_types": [p.get("type") for p in result.get("pii_entities", [])],
            "safe_text": result.get("safe_text", "")[:120] if result.get("safe_text") else None,
            "latency_ms": result.get("latency_ms", 0.0)
        }
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except Exception as e:
        print(f"Logging error: {e}")


def read_logs(limit: int = 50) -> list:
    try:
        if not os.path.exists(LOG_FILE):
            return []
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        logs = [json.loads(line) for line in lines[-limit:]]
        return logs
    except Exception as e:
        print(f"Log read error: {e}")
        return []


def get_latency_stats() -> dict:
    try:
        logs = read_logs(limit=200)
        if not logs:
            return {}
        latencies = [l['latency_ms'] for l in logs if 'latency_ms' in l]
        if not latencies:
            return {}
        latencies.sort()
        n = len(latencies)
        return {
            "count": n,
            "mean_ms": round(sum(latencies) / n, 2),
            "median_ms": round(latencies[n // 2], 2),
            "p95_ms": round(latencies[int(n * 0.95)], 2),
            "min_ms": round(min(latencies), 2),
            "max_ms": round(max(latencies), 2)
        }
    except Exception as e:
        print(f"Latency stats error: {e}")
        return {}