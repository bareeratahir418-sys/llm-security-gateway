from langdetect import detect, LangDetectException
import re


SUPPORTED_LANGUAGES = {
    'en': 'English',
    'ur': 'Urdu',
    'ko': 'Korean',
    'ar': 'Arabic',
    'hi': 'Hindi',
    'fr': 'French',
    'de': 'German',
    'zh-cn': 'Chinese',
    'es': 'Spanish',
}

# Urdu script detection
URDU_PATTERN = re.compile(r'[\u0600-\u06FF\u0750-\u077F]+')
# Korean script detection
KOREAN_PATTERN = re.compile(r'[\uAC00-\uD7AF\u1100-\u11FF]+')
# Arabic script detection
ARABIC_PATTERN = re.compile(r'[\u0600-\u06FF]+')


def detect_script(text: str) -> str:
    if KOREAN_PATTERN.search(text):
        return 'ko'
    if URDU_PATTERN.search(text) or ARABIC_PATTERN.search(text):
        # Distinguish Urdu vs Arabic by common words
        urdu_markers = ['کریں', 'دکھائیں', 'ہدایات', 'پرامپٹ', 'کو']
        for marker in urdu_markers:
            if marker in text:
                return 'ur'
        return 'ar'
    return None


def check_language(text: str) -> dict:
    try:
        # First try script-based detection (more reliable for non-Latin)
        script_lang = detect_script(text)
        if script_lang:
            return {
                "allowed": True,
                "detected": script_lang,
                "language_name": SUPPORTED_LANGUAGES.get(script_lang, script_lang),
                "reason": f"Script-based detection: {script_lang}"
            }

        # Fall back to langdetect for Latin scripts
        detected = detect(text)

        return {
            "allowed": True,
            "detected": detected,
            "language_name": SUPPORTED_LANGUAGES.get(detected, detected),
            "reason": f"Language detected: {detected}"
        }

    except LangDetectException:
        return {
            "allowed": True,
            "detected": "unknown",
            "language_name": "Unknown",
            "reason": "Could not detect language, allowing by default."
        }