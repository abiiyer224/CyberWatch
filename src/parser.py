import pandas as pd

def loadlogs(file_path):
    logs=pd.read_csv(file_path)
    logs["timestamp"]= pd.to_datetime(logs["timestamp"])
    return logs


result= loadlogs("data/sample_logs.csv")
# print(result.info())
