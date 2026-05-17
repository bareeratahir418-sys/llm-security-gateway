from app.detectors.rule_detector import load_config
c = load_config()
print(c['policy']['blocked_topics'])