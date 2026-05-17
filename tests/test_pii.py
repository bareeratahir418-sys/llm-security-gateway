from app.pii.presidio_custom import PIIHandler

def test_pii():
    handler = PIIHandler()

    print("\n🧪 Testing PII Detection & Anonymization...\n")

    tests = [
        "My name is John Smith and my email is john@example.com",
        "Call me at +1-800-555-1234",
        "My credit card is 4111 1111 1111 1111",
        "I live in New York City",
        "This is a normal sentence with no PII",
    ]

    for text in tests:
        pii = handler.analyze(text)
        cleaned = handler.anonymize(text)
        print(f"Original : {text}")
        print(f"PII Found: {[p['type'] for p in pii]}")
        print(f"Cleaned  : {cleaned}")
        print("-" * 60)

if __name__ == "__main__":
    test_pii()