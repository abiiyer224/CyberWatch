import pandas as pd
from src.detection import get_failed_logins, count_ip, detect_brute_force, detect_failed_then_success, detect_suspicious_powershell, detect_admin_account_creation
def test_brute_force_alert_created():

    data = {
        "timestamp": [
            "2026-08-14 10:00:01",
            "2026-08-14 10:00:08",
            "2026-08-14 10:00:15",
            "2026-08-14 10:00:21",
            "2026-08-14 10:00:30"
        ],

        "source_ip": [
            "192.168.1.45",
            "192.168.1.45",
            "192.168.1.45",
            "192.168.1.45",
            "192.168.1.45"
        ],

        "username": [
            "admin",
            "admin",
            "admin",
            "admin",
            "admin"
        ],

        "event_type": [
            "LOGIN_FAILED",
            "LOGIN_FAILED",
            "LOGIN_FAILED",
            "LOGIN_FAILED",
            "LOGIN_FAILED"
        ]
    }
    logs = pd.DataFrame(data)
    failed_logs = get_failed_logins(logs)
    ip_counts = count_ip(failed_logs)
    alerts = detect_brute_force(ip_counts)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "Brute Force"

def test_brute_force_alert1_created():

    data = {
        "timestamp": [
            "2026-08-14 10:00:01",
            "2026-08-14 10:00:08",
            "2026-08-14 10:00:15",
            "2026-08-14 10:00:21"
        ],

        "source_ip": [
            "192.168.1.45",
            "192.168.1.45",
            "192.168.1.45",
            "192.168.1.45"
        ],

        "username": [
            "admin",
            "admin",
            "admin",
            "admin"
        ],

        "event_type": [
            "LOGIN_FAILED",
            "LOGIN_FAILED",
            "LOGIN_FAILED",
            "LOGIN_FAILED"
        ]
    }


    logs = pd.DataFrame(data)

    failed_logs = get_failed_logins(logs)

    ip_counts = count_ip(failed_logs)

    alerts = detect_brute_force(ip_counts)
    assert len(alerts) == 0

def test_account_compromise_alert_created():

    data = {
        "timestamp": [
            "2026-08-14 10:00:01",
            "2026-08-14 10:00:08",
            "2026-08-14 10:00:15",
            "2026-08-14 10:00:21",
            "2026-08-14 10:00:30",
            "2026-08-14 10:00:35"
        ],

        "source_ip": [
            "192.168.1.45",
            "192.168.1.45",
            "192.168.1.45",
            "192.168.1.45",
            "192.168.1.45",
            "192.168.1.45"
        ],

        "username": [
            "admin",
            "admin",
            "admin",
            "admin",
            "admin",
            "admin"
        ],

        "event_type": [
            "LOGIN_FAILED",
            "LOGIN_FAILED",
            "LOGIN_FAILED",
            "LOGIN_FAILED",
            "LOGIN_FAILED",
            "LOGIN_SUCCESS"
        ]
    }
    logs = pd.DataFrame(data)
    alerts = detect_failed_then_success(logs)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "Possible Account Compromise"
    # assert alerts[0]["alert_type"] == "Brute Force"

def test_account_compromise_no_alert_created():

    data = {
        "timestamp": [
            "2026-08-14 10:00:01",
            "2026-08-14 10:00:08"
        ],

        "source_ip": [
            "192.168.1.45",
            "192.168.1.45"
        ],

        "username": [
            "admin",
            "admin"
        ],

        "event_type": [
            "LOGIN_FAILED",
            "LOGIN_SUCCESS"
        ]
    }


    logs = pd.DataFrame(data)
    alerts = detect_failed_then_success(logs)
    assert len(alerts) == 0

def test_ps_alert_created():

    data = {
        "timestamp": [
            "2026-08-14 10:00:01"
        ],

        "source_ip": [
            "192.168.1.45"
        ],

        "username": [
            "admin"
        ],

        "event_type": [
            "POWERSHELL_EXECUTION"
        ],
        "details": [
            "powershell.exe -EncodedCommand ABC123"
        ]
    }
    logs = pd.DataFrame(data)
    alerts = detect_suspicious_powershell(logs)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "Suspicious PowerShell"

def test_ps_no_alert_created():

    data = {
        "timestamp": [
            "2026-08-14 10:00:01"
        ],

        "source_ip": [
            "192.168.1.45"
        ],

        "username": [
            "admin"
        ],

        "event_type": [
            "POWERSHELL_EXECUTION"
        ],
        "details": [
            "powershell.exe Get-Service"
        ]
    }
    logs = pd.DataFrame(data)
    alerts = detect_suspicious_powershell(logs)

    assert len(alerts) == 0
    # assert alerts[0]["alert_type"] == "Suspicious PowerShell"

def test_admin_account_alert_created():

    data = {
        "timestamp": [
            "2026-08-14 10:05:00"
        ],

        "source_ip": [
            "192.168.1.50"
        ],

        "username": [
            "abi"
        ],

        "event_type": [
            "ADMIN_ACCOUNT_CREATED"
        ],

        "details": [
            "Hired a new admin"
        ]
    }

    logs = pd.DataFrame(data)

    alerts = detect_admin_account_creation(logs)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "Admin Account Creation"