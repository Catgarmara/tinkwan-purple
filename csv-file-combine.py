import pandas as pd
import os
from glob import glob

# Set the directory containing your 186 CSV files
input_dir = "C:\Users\Tyler Sin\Desktop\PWC daily reports"
output_file = "web-attack-report-20250328-20250706.csv"

# Collect all CSV file paths
csv_files = glob(os.path.join(input_dir, "*.csv"))

# Read and concatenate
df_list = [pd.read_csv(f) for f in csv_files]
combined_df = pd.concat(df_list, ignore_index=True)

# Optional: sort by timestamp
combined_df.sort_values(by="timestamp", inplace=True)

# Save
combined_df.to_csv(output_file, index=False)
