import matplotlib.ticker as mticker
import matplotlib.pyplot as plt
import re
import os
import sys

def get_xy(size_key, y_key, data):
    xs = list(data[size_key].keys())
    ys = [data[size_key][k][y_key] for k in xs]
    return xs, ys


def parse_filename(filepath, lf_type=None):
    filename = os.path.basename(filepath)
    
    pattern = r"out_.*?(\d+)_([^_]+)_((zs|ds)_.+)\.log"
    #pattern = r"out_.*?(\d+)_([^_]+)_((zs|ds)_[^_]+)\.log"
    match = re.match(pattern, filename)
    
    if not match:
        return None
    
    size = int(match.group(1))
    insn = match.group(2)
    lf_full = match.group(3)   
    lf_prefix = match.group(4)
   
    if lf_type is not None and lf_prefix != lf_type:
        return None
 
    size_key = f"{size}x{size}"
    insn_label = f"{insn.lower()} {lf_full.lower()}"
    
    return size_key, insn_label


def parse_log_file(filepath):
    with open(filepath, 'r') as f:
        text = f.read()
    
    runtime_match = re.search(r"Total runtime:\s*([0-9.]+)", text)
    queries_match = re.search(r"Number of queries:\s*(\d+)", text)
    symb_insns_match = re.search(r"Found (\d+) instructions \((\d+) .*?\) after stepping (\d+) times", text)  

    return {
        "runtime": float(runtime_match.group(1)) if runtime_match else None,
        "queries": int(queries_match.group(1)) if queries_match else None,
        "symb_insns": int(symb_insns_match.group(2)) if symb_insns_match else None
    }


def build_data_runtime(directory, lf_type):
    data_runtime = {}
    for filename in os.listdir(directory):
        if not filename.endswith(".log"):
            continue
        
        filepath = os.path.join(directory, filename)
        
        parsed = parse_filename(filepath, lf_type)
        if parsed is None:
            print(f"Skipping: {filename}")
            continue
        
        size_key, insn_label = parsed
        metrics = parse_log_file(filepath)
        
        if size_key not in data_runtime:
            data_runtime[size_key] = {}
        
        data_runtime[size_key][insn_label] = metrics
    
    return data_runtime


def fmt_e(v, pos):
    if v == 0:
        return "0"
    mant, exp = f"{v:.0e}".replace("+", "").split("e")  # e.g., "2e05" -> ["2","05"]
    return f"{mant}e{int(exp)}"                          # -> "2e5"

path = sys.argv[1] 
data_runtime = build_data_runtime(path, "zs")
print(data_runtime)

fig, axes = plt.subplots(2, 2, figsize=(5, 3.2))

# (row 0, col 0)
ax = axes[0,0]
ax.set_yscale('log')
ax.set_ylabel("SMT queries", fontsize=12)

_, symb_insns = get_xy("3x3", "symb_insns", data_runtime)
_, queries = get_xy("3x3", "queries", data_runtime)
ax.scatter(symb_insns, queries, label="3x3")

_, symb_insns = get_xy("2x2", "symb_insns", data_runtime)
_, queries = get_xy("2x2", "queries", data_runtime)
ax.scatter(symb_insns, queries, color="g", label="2x2")

ax.legend(loc='lower right', fontsize=8)

# (row 1, col 0)
ax = axes[1,0]
ax.set_xlabel("# instrumented insns", fontsize=12)
ax.set_ylabel("Runtime (s)", fontsize=12)

x_labels, runtimes = get_xy("3x3", "runtime", data_runtime)
_, symb_insns = get_xy("3x3", "symb_insns", data_runtime)
ax.scatter(symb_insns, runtimes, label="3x3")

x_labels, runtimes = get_xy("2x2", "runtime", data_runtime)
_, symb_insns = get_xy("2x2", "symb_insns", data_runtime)
ax.scatter(symb_insns, runtimes, color='g', label="2x2")

ax.legend(loc='best',fontsize=8)

data_uobs = build_data_runtime(path, "ds")
print(data_uobs)
transform = {"ds_op2_8bit": 1, "ds_op2_4bit": 2, "ds_op2_2bit": 4, "ds_op2_1bit": 8} 

# (row 0, col 1)
ax = axes[0,1]
ax.set_xscale('log')
ax.set_yscale('log')

x, y = get_xy("3x3", "queries", data_uobs)
new_x = list(map(lambda i: transform[i.split()[-1]], x))
ax.scatter(new_x, y, marker="o", label="3x3")

x, y = get_xy("2x2", "queries", data_uobs)
new_x = list(map(lambda i: transform[i.split()[-1]], x))
ax.scatter(new_x, y, marker="o", color="g",label="2x2")

ax.legend(loc='lower right',fontsize=8)
ax.set_xticks(sorted(set(new_x)))
ax.xaxis.set_minor_locator(mticker.NullLocator())
ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda v, pos: f"{int(v)}"))


# (row 1, col 1)
ax = axes[1,1]
ax.set_xscale('log')

x, y = get_xy("3x3", "runtime", data_uobs)
new_x = list(map(lambda i: transform[i.split()[-1]], x))
ax.scatter(new_x, y, marker="o",label="3x3")

x, y = get_xy("2x2", "runtime", data_uobs)
new_x = list(map(lambda i: transform[i.split()[-1]], x))
ax.scatter(new_x, y, marker="o", color="g",label="2x2")

ax.set_xlabel("# \u03BCobs / \u03BCobs func", fontsize=12)
ax.legend(loc='upper left',fontsize=8)
ax.set_xticks(sorted(set(new_x)))
ax.xaxis.set_minor_locator(mticker.NullLocator())
ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda v, pos: f"{int(v)}"))


fig.tight_layout()
outpath = f"{path}/Figure_8_scalability_eval.pdf"
fig.savefig(outpath, format="pdf")
plt.close(fig)

print(f"Wrote {outpath}")
