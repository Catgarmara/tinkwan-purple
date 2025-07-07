import pandas as pd
import os
from glob import glob

input_dir = r"C:\Users\Tyler Sin\Desktop\PWC daily reports"
output_file = r"C:\Users\Tyler Sin\Desktop\web-attack-report-20250328-20250706.csv"

csv_files = glob(os.path.join(input_dir, "*.csv")) + glob(os.path.join(input_dir, "*.CSV"))

df_list = []
for f in csv_files:
    try:
        df = pd.read_csv(f)
        df_list.append(df)
    except Exception as e:
        print(f"Failed to read {f}: {e}")

if not df_list:
    print("No valid CSVs to combine.")
else:
    combined_df = pd.concat(df_list, ignore_index=True)

    if "timestamp" in combined_df.columns:
        combined_df.sort_values(by="timestamp", inplace=True)

    combined_df.to_csv(output_file, index=False)
    print(f"Combined file written to: {output_file}")
