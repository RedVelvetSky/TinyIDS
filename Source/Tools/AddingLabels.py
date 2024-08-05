import pandas as pd

# input_csv = "E:\Stuff\IDS Machine Learning\Source\Tools\malicious_traffic2.csv"
# output_csv = "E:\Stuff\IDS Machine Learning\Dataset\Train\\malicious_traffic_labeled.csv"

input_csv = "E:\Stuff\IDS Machine Learning\Dataset\Train\\benign_traffic_exp1.csv"
output_csv = "E:\Stuff\IDS Machine Learning\Dataset\Train\\benign_traffic_labeled.csv"

df = pd.read_csv(input_csv)
df['IsMalicious'] = False
df = df.head(120000) # slicing up to the first 120.000 rows
df.to_csv(output_csv, index=False)

print(f"New CSV file with 'is_malicious' column has been saved as '{output_csv}'")
