import matplotlib.ticker as mticker
import re
import os
import math
import matplotlib.pyplot as plt
import sys

def extract_path_counts(file_path):
    # Reads the input file and returns a list of (path_number, count).
    all_vars = ["r0", "r1", "r2", "r3"]
    directory = os.path.dirname(file_path)
    path_counts = []
    current_path = None

    pattern_path = re.compile(r"^Path\s+(\d+):")
    pattern_count = re.compile(r"^Model count:\s*(\d+)", re.MULTILINE)

    with open(file_path, 'r') as f:
        for line in f:
            # Capture path number
            m_path = pattern_path.match(line)
            if m_path:
                current_path = int(m_path.group(1))
                continue

            # Capture model count
            m_count = pattern_count.match(line)
            if m_count and current_path is not None:
                count = int(m_count.group(1))

                # Check the corresponding SMT2 file for the declaration line
                # Hacky way of making sure BV solver did not optimize away r0
                smt2_filename = os.path.join(directory, f"path{current_path}.smt2")
                has_declare = [False]*len(all_vars)
                if os.path.exists(smt2_filename):
                    with open(smt2_filename, 'r') as smt2_file:
                        for smt2_line in smt2_file:
                            for i in range(len(all_vars)):
                                if f"declare-fun {all_vars[i]}" in smt2_line:
                                    has_declare[i] = True
                            if all(has_declare):
                                break

                # If the declaration is missing, adjust the count
                for x in has_declare: 
                    if not x:
                        count *= 2**32

                path_counts.append((current_path, count))
                current_path = None

    return path_counts


def compute_probs(file_path, results=None):
    # Usage example
    if results == None:
        path_counts = extract_path_counts(file_path)
    
        # Extract just the counts and proceed with plotting
        counts = [count for _, count in path_counts]
        #print(f"Total = {math.log2(sum(counts))}")

        # Sort in ascending order
        counts_sorted = sorted(counts)
        divisor = 2**128
    
    else:
        counts = list(results.values())
        counts_sorted = sorted(counts)
        divisor = sum(counts_sorted)

    probs = list()
    x_vals = []
    y_vals = []
    
    running_sum = 0
    x_vals.append(0)
    for i, v in enumerate(counts_sorted):
        running_sum += v
        probs.append(v / divisor)
        if i != (len(counts_sorted)-1):
            x_vals.append((running_sum / divisor))
        y_vals.append(math.log2(divisor / v))

    #print(f"Total prob = {sum(probs)}")
    return probs, x_vals, y_vals, counts, counts_sorted


import sys

if len(sys.argv) != 4:
    print("Usage: python3 plot_pml_results.py <results_file_1> <results_file_2> <output_file_path>")
    sys.exit(1)

arg1 = sys.argv[1]
arg2 = sys.argv[2]
arg3 = sys.argv[3]

fig, axs = plt.subplots(1, 2, figsize=(10, 5), sharey='row', sharex='row')

file_path1 = arg1
probs1, x_vals1, y_vals1, counts1, counts_sorted1 = compute_probs(file_path1)
axs[1].step(y_vals1, x_vals1, marker='o', linestyle='-', label="Digit-serial multiplier", where="post")

file_path2 = arg2 
probs2, x_vals2, y_vals2, counts2, counts_sorted2 = compute_probs(file_path2)
axs[0].step(y_vals2, x_vals2, marker='o', linestyle='-', label="Zero-skip multiplier", where="post", color="g")

fig.suptitle("Poly1305 tail-bound security guarantees for two multiplication optimizations", fontsize=14)

axs[0].set_title("Zero-skip multiplier")
axs[1].set_title("Digit-serial multiplier")
#plt.xscale('log', base=2)
#plt.yscale('log')
axs[0].set_xlabel("\u03B5")
axs[1].set_xlabel("\u03B5")

axs[0].set_ylabel("\u03B4")
axs[1].set_ylabel("\u03B4")
axs[0].grid(True)
axs[1].grid(True)

y_formatter = mticker.FormatStrFormatter('%1.1e')

# Save plot
#output_fp = 'poly1305_results_two_plots.pdf'
#print(f"Writing: {output_fp}")
#plt.savefig(output_fp, dpi=300)

plt.figure(figsize=(5, 2.5), constrained_layout=True)
#plt.subplots_adjust(bottom=0.18, top=.9) 
plt.step(y_vals1, x_vals1, marker="o", markersize=6, linestyle='-', label="Digit-serial multiplier", where="post", color="g")
plt.step(y_vals2, x_vals2, marker="o", markersize=6, linestyle='-', label="Zero-skip multiplier", where="post", color="b")
#print(x_vals1)
#print(y_vals1)
plt.annotate(
    f'({y_vals1[-1]:.2f}, {x_vals1[-1]:.2f})',       
    (y_vals1[-1], x_vals1[-1]),              
    textcoords="offset points",
    xytext=(39, -7),            
    ha='center',
    color='g',                
    fontsize=10,
    bbox=dict(facecolor='white', alpha=0.7, edgecolor='none')  
)

plt.annotate(
    f'({y_vals2[-1]:.2e}, {x_vals2[-1]:.2e})',
    (y_vals2[-1], x_vals2[-1]),
    xytext=(-13, 10),           
    textcoords="offset points",
    ha='left',
    color='b',              
    fontsize=10,
    bbox=dict(facecolor='white', alpha=0.7, edgecolor='none')
)

plt.xlabel("$\epsilon$",fontsize=12)
plt.ylabel("$\delta$", fontsize=12)
plt.grid(True)
#plt.title("Tail-bound guarantees for Poly1305 under\nmultiplication optimizations", fontsize=12, pad=6)
plt.legend()
output_fp = arg3
print(f"Writing: {output_fp}")
plt.savefig(output_fp, format="pdf", dpi=300)
