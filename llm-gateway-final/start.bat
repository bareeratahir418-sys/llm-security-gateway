@echo off
echo Starting LLM Gateway...
cd C:\Users\LENOVO\llm-gateway-final
call venv\Scripts\activate
uvicorn app.main:app --reload --port 8000
pause