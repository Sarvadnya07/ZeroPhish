import time
import re

# Simulate a typical load: 10,000 links
links = [
    f"http://192.168.1.{i}/index.html" if i % 10 == 0
    else f"http://example.zip/page{i}" if i % 15 == 0
    else f"http://example.com/page{i}"
    for i in range(10000)
]

# Baseline (current implementation)
start = time.perf_counter()
link_score = 0
for link in links:
    lowered_link = link.lower()
    if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)", lowered_link):
        link_score += 20
    if re.search(r"\.(zip|mov|top|xyz|click|country|stream|gq|tk|ml|ga|cf)(?:/|$)", lowered_link):
        link_score += 10

baseline_time = time.perf_counter() - start
print(f"Baseline Time: {baseline_time:.6f} seconds")

# Optimized implementation
IP_REGEX = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)")
SUSPICIOUS_TLD_REGEX = re.compile(r"\.(zip|mov|top|xyz|click|country|stream|gq|tk|ml|ga|cf)(?:/|$)")

start = time.perf_counter()
link_score = 0
for link in links:
    lowered_link = link.lower()
    if IP_REGEX.search(lowered_link):
        link_score += 20
    if SUSPICIOUS_TLD_REGEX.search(lowered_link):
        link_score += 10

optimized_time = time.perf_counter() - start
print(f"Optimized Time: {optimized_time:.6f} seconds")

improvement = ((baseline_time - optimized_time) / baseline_time) * 100
print(f"Improvement: {improvement:.2f}%")
