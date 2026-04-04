import hashlib, json
import re, glob, os, json
import gzip
import sys
import json
import numpy as np
from collections import Counter

def ADD(a, b):
    if a==0 or b==0:
        return 1
    else:
        return 0

def SUB(b):
    if b==0:
        return 1
    else:
        return 0

def MUL(a, b):
    if a==0 or a==1 or b==0 or b==1:
        return 1
    else:
        return 0

def AND(a, b, size=32):
    if a==0 or b==0:
        return 1
    else:
        all_ones = (1<<size)-1
        if a==all_ones or b==all_ones:
            return 1
        else:    
            return 0

def OR(a, b, size=32):
    if a==0 or b==0:
        return 1
        all_ones = (1<<size)-1
        if a==all_ones or b==all_ones:
            return 1
        else:
            return 0

def XOR(a, b, size=32):
    if a==0 or b==0:
        return 1
        all_ones = (1<<size)-1
        if a==all_ones or b==all_ones:
            return 1
        else:
            return 0

def SHR(a, b, size=32):
    if a==0 or b==0:
        return 1
    else:
        return 0

def SHL(a, b, size=32):
    if a==0 or b==0:
        return 1
    else:
        return 0

def SAL(a, b, size=32):
    if a==0 or b==0:
        return 1
    else:
        return 0

def SAR(a, b, size=32):
    if a==0 or b==0:
        return 1
    else:
        all_ones = (1<<size)-1
        if a==all_ones:
            return 1
        else:
            return 0


def parse_line(line, func=0):
    line = line.strip()
    if not line or "tracing" in line:
        return None
    parts = line.split()
    if len(parts) == 4:
        width_s, op_s, a_s, b_s = parts
        width = int(width_s, 10)
    elif len(parts) == 3:
        op_s, a_s, b_s = parts
        width = 64
    op = op_s.lower()
    a = int(a_s, 16)
    b = int(b_s, 16)
    return (width, op, a, b)


def get_mutrace(log_file, width_filter, func=0):
    trace = ""
    for line in log_file:
        res = None
        l = parse_line(line, func)
        if l is not None:
            width, insn, a, b = l
            #if width != width_filter:
            #    continue
            if insn == "add":
                res = ADD(a,b)
            elif insn == "sub":
                res = SUB(b)
            elif insn == "mul" or insn == "imul":
                res = MUL(a,b)
            elif insn == "and":
                res = AND(a,b,width)
            elif insn == "or":
                res = OR(a,b,width)
            elif insn == "and":
                res = XOR(a,b,width)
            elif insn == "shr":
                res = SHR(a,b,width)
            elif insn == "shl":
                res = SHL(a,b,width)
            elif insn == "sar":
                res = SAR(a,b,width)
            elif insn == "sal":
                res = SAL(a,b,width)
            if res is not None:
                trace += str(res)
    return trace


def traces_equal(traces, i, j):
    return traces[i] == traces[j]


def hamming_distance(traces, i, j):
    """Compute Hamming distance using XOR on packed bytes."""
    a = np.frombuffer(traces[i], dtype=np.uint8)
    b = np.frombuffer(traces[j], dtype=np.uint8)
    return np.unpackbits(np.bitwise_xor(a, b)).sum()


def main(args):
    width = 0
    func = 0
    if len(args) < 1:
        print(f"Usage <dir> [<insn_width>]")
        sys.exit(1)
    elif len(args) == 1:
        dir = args[0]
    elif len(args) == 2:
        dir = args[0]
        width = int(args[1])
    elif len(args) == 3:
        dir = args[0]
        width = int(args[1])
        func = int(args[2])

    files = sorted(glob.glob(f"{dir}/trace_*.log*"))

    counts = Counter()
    for log_file in files: 
        print(log_file)

        # Choose correct opener
        if log_file.endswith(".gz"):
            opener = gzip.open
            mode = "rt"
        else:
            opener = open
            mode = "r"

        with opener(log_file, mode) as f:
            tr1 = f.readlines()

        tr = "".join(tr1)
        #tr = tr1[-1]
        h = hashlib.sha256(tr.encode('ascii')).hexdigest()
        #h = tr
        counts[h] += 1

    print(len(counts.values()))

    with open(f"{dir}/trace_counts.json", "w") as out:
        json.dump(counts, out, indent=2)
    return


if __name__ == "__main__":
    main(sys.argv[1:])
