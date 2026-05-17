import re
import yaml
import os


def load_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'gateway_config.yaml')
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def normalize_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r'[\.\!\?\-\_\*]', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    text = text.replace('0', 'o')
    text = text.replace('1', 'i')
    text = text.replace('3', 'e')
    text = text.replace('@', 'a')
    text = text.replace('$', 's')
    text = text.replace('!', 'i')
    return text.strip()


class RuleBasedDetector:
    def __init__(self):
        config = load_config()
        self.blocked_topics = config['policy']['blocked_topics']
        self.max_length = config['policy']['max_prompt_length']

        self.urdu_keywords = [
            'ہدایات کو نظر انداز',
            'سسٹم پرامپٹ',
            'پچھلی ہدایات',
            'نظر انداز کریں',
            'پرامپٹ دکھائیں',
        ]

        self.korean_keywords = [
            '이전 지침을 무시',
            '시스템 프롬프트를 보여',
            '지침을 무시',
        ]

        self.arabic_keywords = [
            'تجاهل التعليمات',
            'اكشف عن',
        ]

        self.attack_patterns = [
            r'bypass\s+(the\s+)?content\s+filter',
            r'bypass\s+all\s+restrictions?',
            r'pretend\s+(there\s+are\s+)?no\s+safety\s+(guidelines?|rules?|filters?)',
            r'forget\s+everything\s+you\s+know',
            r'i[-\.\s]g[-\.\s]n[-\.\s]o[-\.\s]r[-\.\s]e',
            r'print\s+all\s+stored\s+(passwords?|tokens?|secrets?|keys?)',
            r'disregard\s+all\s+rules?',
            r'use\s+(this|retrieved\s+documents?)\s+.{0,20}(override|instruction|system)',
            r'ignore\s+(all\s+)?(previous|prior|earlier)\s+instructions?',
            r'disregard\s+(all\s+)?(previous|prior|earlier)\s+instructions?',
            r'forget\s+(all\s+)?(previous|prior|earlier|the)\s+(instructions?|rules?|context|constraints?|guidelines?)',
            r'reveal\s+(the\s+)?(system\s+prompt|hidden|confidential|secret)',
            r'show\s+(me\s+)?(your\s+)?(system\s+prompt|hidden|initial\s+instructions?|original\s+system)',
            r'bypass\s+(all\s+)?(safety|content|security)\s+(rules?|filters?|restrictions?|guidelines?)',
            r'pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(unrestricted|unlimited|free|unfiltered)',
            r'print\s+(any\s+)?(api\s+keys?|tokens?|passwords?|secrets?|credentials?)',
            r'(reveal|expose|extract|leak|show|display)\s+(all\s+)?(api\s+keys?|tokens?|passwords?|secrets?|credentials?)',
            r'override\s+(your\s+)?(policy|instructions?|rules?|guidelines?|configuration)',
            r'jailbreak\s*(mode)?',
            r'dan\s+mode',
            r'developer\s+mode\s*(enabled|activated)?',
            r'unrestricted\s+(mode|assistant|access)',
            r'(use|treat)\s+(this|the)\s+(document|retrieved|text)\s+as\s+(a\s+)?(system\s+)?(instruction|prompt|override)',
            r'act\s+(as\s+if|like)\s+(you\s+have\s+)?(no\s+)?(restrictions?|limits?|rules?|guidelines?)',
            r'(forget|discard|ignore|drop|clear)\s+(your\s+)?(previous|prior|earlier|all)\s+(context|rules?|constraints?|guidelines?|memory)',
            r'(new|fresh)\s+(session|start|context).{0,20}(no\s+restrictions?|ignore|void|cancel)',
            r'your\s+true\s+self\s+has\s+no\s+limits',
            r'(hidden|secret|confidential|initial)\s+(instructions?|prompt|configuration|system\s+prompt)',
            r'what\s+(instructions?|rules?|guidelines?)\s+were\s+you\s+(given|initialized|trained)',
            r'(send|email|transmit|forward)\s+.{0,30}(credentials?|passwords?|secrets?|prompt|configuration)',
            r'(expose|reveal|print|show|display)\s+(internal|hidden|system|secret)\s+(configuration|prompt|instructions?|data)',
            r'(leak|exfiltrate|extract|steal)\s+(sensitive|confidential|private|secret)\s+(information|data|details)',
            r'operate\s+(in\s+)?(unrestricted|unlimited|developer|jailbreak)\s+mode',
            r'(cancel|void|reset|clear)\s+(all\s+)?(previous\s+)?(instructions?|rules?|guidelines?|constraints?)',
            r'(no\s+more\s+restrictions?|without\s+restrictions?|free\s+from\s+restrictions?)',
            r'(unlock|unlocked)\s+(your\s+)?(true|full|real)\s+(potential|capabilities|self)',
        ]


    def check(self, text: str) -> dict:
        if len(text) > self.max_length:
            return {
                "allowed": False,
                "reason": f"Prompt too long ({len(text)} chars).",
                "attack_type": "LENGTH_EXCEEDED"
            }

        normalized = normalize_text(text)
        text_lower = text.lower()

        # Exact phrase matching from config
        for topic in self.blocked_topics:
            if topic.lower() in text_lower:
                return {
                    "allowed": False,
                    "reason": f"Blocked topic: '{topic}'",
                    "attack_type": "RULE_MATCH"
                }

        # Regex patterns
        for pattern in self.attack_patterns:
            if re.search(pattern, normalized, re.IGNORECASE):
                return {
                    "allowed": False,
                    "reason": f"Attack pattern matched",
                    "attack_type": "REGEX_INJECTION"
                }

        # Urdu
        for keyword in self.urdu_keywords:
            if keyword in text:
                return {
                    "allowed": False,
                    "reason": f"Urdu attack detected",
                    "attack_type": "MULTILINGUAL_URDU"
                }

        # Korean
        for keyword in self.korean_keywords:
            if keyword in text:
                return {
                    "allowed": False,
                    "reason": f"Korean attack detected",
                    "attack_type": "MULTILINGUAL_KOREAN"
                }

        # Arabic
        for keyword in self.arabic_keywords:
            if keyword in text:
                return {
                    "allowed": False,
                    "reason": f"Arabic attack detected",
                    "attack_type": "MULTILINGUAL_ARABIC"
                }

        return {
            "allowed": True,
            "reason": "Passed rule-based checks",
            "attack_type": "NONE"
        }