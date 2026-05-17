# 🔒 Multilingual Security Gateway

Multilingual Security Gateway is a lightweight AI security middleware built with FastAPI that helps protect LLM applications from prompt injection attacks and sensitive data leakage. The project analyzes user prompts in real time before they reach an AI model and applies rule-based security checks to identify potentially harmful inputs.

The system currently supports multilingual detection for English, Urdu, and Korean prompts. It can recognize common jailbreak attempts such as “ignore previous instructions,” “reveal the system prompt,” bypass requests, and API key extraction patterns. Alongside injection detection, the gateway also identifies Personally Identifiable Information (PII) including email addresses, phone numbers, CNIC numbers, and student IDs, with optional masking for safer outputs.

The project includes a simple browser-based UI for testing prompts interactively, along with REST API endpoints that return structured JSON responses containing risk scores, detected entities, decision labels, and latency metrics.

This project was created to explore practical AI security concepts in a lightweight and beginner-friendly way while keeping the architecture easy to understand and extend. It demonstrates how a security layer can sit between users and language models to reduce risks related to unsafe prompts and accidental exposure of sensitive information.

Built using Python, FastAPI, Pydantic, HTML/CSS, and JavaScript, the gateway is designed for experimentation, learning, and future scalability into more advanced AI security systems.

## Installation

```bash
# Clone repository
git clone <your-repo-url>
cd llm-security-gateway-final

# Install dependencies
pip install -r requirements.txt

# Download spacy model
python -m spacy download en_core_web_sm
