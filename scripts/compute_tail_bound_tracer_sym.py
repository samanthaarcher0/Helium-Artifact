import math
import sys
import numpy as np

def parse_model_counts(file_path):
    model_counts = []

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith("Model count:"):
                count_str = line.split(":", 1)[1].strip()
                try:
                    model_counts.append(int(count_str))
                except ValueError:
                    model_counts.append(count_str)

    return model_counts

file_path = sys.argv[1]
if (len(sys.argv)) > 2:
    label = sys.argv[2]
else:
    label = None
counts = parse_model_counts(file_path)
counts = np.array(counts)
#print(counts)
total = sum(counts)
log = math.log2(total)
#print(f"total = {total}\n log={log}\n diff = {total-2**log}")
max_counts = max(counts)
#print(f"max = {max_counts}")
rest = counts < max_counts
rest_counts = counts[rest]
#print(rest_counts)
ep = math.log2(total/max_counts)
delt = sum(rest_counts) / total

if label is None:
    print(f"Possible tail-bound guarantee: P[PML <= {ep}] >= 1 - {delt} = {(1 - delt)}")
else:
    print(f"{label} | {len(counts)} | {ep:.4f} | {delt:.4f} | P[PML <= {ep:.4f}] >= {(1 - delt):.4f}")
