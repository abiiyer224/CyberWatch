CyberWatch

CyberWatch is a cybersecurity project I built to understand how security logs can be parsed, analyzed, and turned into useful alerts.

The project uses Python-based detection rules to identify suspicious activity and a local Ollama model to help explain alerts and suggest investigation steps. The results are displayed through a Streamlit dashboard.

Features
Detects repeated failed login attempts
Detects failed logins followed by a successful login
Detects suspicious PowerShell activity
Detects admin account creation
Generates structured alerts with severity levels
Uses Ollama for local AI-assisted alert analysis
Displays alerts through a Streamlit dashboard
Includes automated tests using Pytest
Tech Stack

Python, Pandas, Streamlit, Pytest, Requests, Ollama, Llama 3.2

How It Works
Security Logs
    ↓
Parser
    ↓
Detection Rules
    ↓
Structured Alerts
    ↓
Streamlit Dashboard
    ↓
AI-Assisted Investigation

The detection logic is handled using Python rules, while the AI is only used after an alert is generated to provide additional context and investigation guidance.

Run
pip install -r requirements.txt
ollama pull llama3.2:3b
streamlit run app.py
Testing
python -m pytest -v
Future Improvements

I plan to add more detection rules, time-based detection, MITRE ATT&CK mapping, and alert storage.