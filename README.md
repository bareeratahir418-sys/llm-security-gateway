# LLM Security Gateway

A secure gateway for LLM applications that detects prompt injection, jailbreak attempts, and sensitive PII.

## Features
- Prompt injection and jailbreak detection
- PII detection and masking (Email, Phone, API Key, CNIC, IP Address)
- Configurable policy engine (Allow / Mask / Block)
- Latency measurement

## Installation

1. Make sure Python 3.x is installed
2. Install dependencies:
pip install flask presidio-analyzer presidio-anonymizer

## How to Run

1. Start the server:
py app.py

2. Send a test request:
py test.py

## API Usage
Send a POST request to http://127.0.0.1:5000/analyze
with JSON body: {"text": "your input here"}
