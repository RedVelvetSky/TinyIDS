import pandas as pd

file1 = "E:\Stuff\IDS Machine Learning\Dataset\Train\\benign_traffic_labeled.csv"
file2 = "E:\Stuff\IDS Machine Learning\Dataset\Train\malicious_traffic_labeled.csv"
output_csv = "E:\Stuff\IDS Machine Learning\Dataset\Train\\train.csv"

df1 = pd.read_csv(file1)
df2 = pd.read_csv(file2)
combined_df = pd.concat([df1, df2])
# reset the index
combined_df.reset_index(drop=True, inplace=True)

df = combined_df

# Convert 'DestinationPort' to strings without the decimal part
df['DestinationPort'] = df['DestinationPort'].apply(lambda x: str(int(x)) if pd.notnull(x) else '')

# Convert 'Ttl' to integers
df['Ttl'] = df['Ttl'].apply(lambda x: int(x) if pd.notnull(x) else '')

df.to_csv(output_csv, index=False)



print(f"The two CSV files have been combined and saved as '{output_csv}'")
