import csv
from collections import Counter

with open("200list.txt", "r", encoding="utf-8") as f:
    lines = f.readlines()

cleaned = [line.strip() for line in lines if line.strip()]
count = Counter(cleaned)

with open("200url_frequency.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["url", "frequency"])
    for url, freq in count.most_common():
        writer.writerow([url, freq])
