from src.parser import loadlogs

def get_failed_logins(logs):
    result= logs["event_type"]== "LOGIN_FAILED"
    failed_logs=logs[result]
    return failed_logs

def count_ip(failed_logs): 
    grouped= failed_logs.groupby("source_ip")
    result= grouped.size()
    return result




logs=loadlogs("data/sample_logs.csv")
fail=get_failed_logins(logs)
ipfail=count_ip(fail)
print(ipfail)