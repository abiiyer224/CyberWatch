import requests


def analyze_alert(alert):
    prompt= f"""You are assisting a SOC analyst.
        Analyze this security alert:
        {alert}

        Rules:
        - Use only the evidence provided in the alert.
        - Do not invent IP reputation, attacker identity, malware, geography, or additional events.
        - Clearly separate confirmed evidence from possible explanations.
        - Do not claim compromise or malicious activity is confirmed unless the evidence proves it.
        - Recommend investigation before containment unless immediate action is clearly justified.

        Return:
        1. Summary
        2. Why suspicious
        3. Evidence
        4. Investigation steps
        5. Recommended response
        """
    
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "llama3.2:3b",
            "prompt": prompt,
            "stream": False
        },
        timeout=60
    ) 
    response.raise_for_status()
    result = response.json()

    return result["response"]
