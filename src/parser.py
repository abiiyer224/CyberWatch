import pandas as pd

def loadlogs(file_path):
    logs=pd.read_csv(file_path)
    return logs


result= loadlogs("data/sample_logs.csv")
print(result)
print(result.info())
print(result.shape)