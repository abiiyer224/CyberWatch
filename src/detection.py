from src.parser import loadlogs
from src.alerts import create_brute_force_alert, create_account_compromise_alert, create_suspicious_powershell_alert, create_admin_account_alert


def get_failed_logins(logs):
    result= logs["event_type"]== "LOGIN_FAILED"
    failed_logs=logs[result]
    return failed_logs

def count_ip(failed_logs): 
    grouped= failed_logs.groupby("source_ip")
    result= grouped.size()
    return result


def detect_brute_force(ipfail):
    alerts_ls=[]
    condition = ipfail >= 5
    suspicious_ips = ipfail[condition]
    for k,v in suspicious_ips.items():
        alert = create_brute_force_alert(k,v)
        alerts_ls.append(alert)
    return alerts_ls

def detect_failed_then_success(logs):
    alerts_ls=[]
    sorted_logs=logs.sort_values(by='timestamp',ascending=True)
    grouped1=sorted_logs.groupby(["source_ip", "username"])
    for (source_ip, username),group in grouped1:
        failed_count=0
        for index, row in group.iterrows():
            if row["event_type"] == "LOGIN_FAILED":
                failed_count += 1

            elif row["event_type"] == "LOGIN_SUCCESS":
                if failed_count >= 5:
                    alert=create_account_compromise_alert(source_ip, username, failed_count)
                    alerts_ls.append(alert)
                failed_count=0
    return alerts_ls

def detect_suspicious_powershell(logs):
    alerts_ls=[]
    result= logs["event_type"]== "POWERSHELL_EXECUTION"
    ps_logs=logs[result]
    for index, row in ps_logs.iterrows():
        if ("-EncodedCommand" in row["details"]) or ("Invoke-WebRequest" in row["details"]) or ("DownloadString" in row["details"]) or ("IEX" in row["details"]):
            alert=create_suspicious_powershell_alert(row["source_ip"], row["username"], row["details"])
            alerts_ls.append(alert)
    return alerts_ls

def detect_admin_account_creation(logs):
    alerts_ls=[]
    result= logs["event_type"]== "ADMIN_ACCOUNT_CREATED"
    ad_logs=logs[result]
    for index, row in ad_logs.iterrows():
        alert=create_admin_account_alert(row["source_ip"], row["username"], row["details"])
        alerts_ls.append(alert)
    return alerts_ls
if __name__ == "__main__":
    logs=loadlogs("data/sample_logs.csv")
    fail=get_failed_logins(logs)
    ipfail=count_ip(fail)
    
    print(detect_failed_then_success(logs))
    print(detect_brute_force(ipfail))
    print(detect_suspicious_powershell(logs))
    print(detect_admin_account_creation(logs))
    #print(brute_force)