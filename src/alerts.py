def create_brute_force_alert(source_ip,fail):
    dic={"alert_type": "Brute Force", "severity": "High", "source_IP": source_ip,"description":"Multiple failed login attempts detected from the same source IP.","evidence":fail}
    return dic

def create_account_compromise_alert(source_ip, username, failed_count):
    dic1={"alert_type": "Possible Account Compromise", "severity": "Critical","source_IP": source_ip,"username":username,"description": "Multiple failed login attempts were followed by a successful login.","evidence": failed_count}
    return dic1

def create_suspicious_powershell_alert(source_ip, username, details):
    dic2={"alert_type": "Suspicious PowerShell", "severity": "Medium","source_IP": source_ip,"username":username,"description": "Suspicious PowerShell command pattern detected.","evidence": details}
    return dic2

def create_admin_account_alert(source_ip, username, details):
    dic3={"alert_type": "Admin Account Creation", "severity": "High","source_IP": source_ip,"username":username,"description": "Admin creation detected.","evidence": details}
    return dic3