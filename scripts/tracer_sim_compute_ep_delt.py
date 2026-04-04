from collections import Counter
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import beta
import json
import sys
import math

def compute_pml(k, n):
    p_est = k/n
    p_low, p_high = clopper_pearson(k, n, alpha=0.05)
    pml = math.log2(1/p_est)
    pml_high = math.log2(1/p_low)
    pml_low = math.log2(1/p_high)
    return pml, pml_low, pml_high


def clopper_pearson(k, n, alpha=0.05):
    if n <= 0:
        raise ValueError("n must be positive")
    if not (0 <= k <= n):
        raise ValueError("k must be between 0 and n")
    low  = 0.0 if k == 0 else beta.ppf(alpha/2, k, n-k+1)
    high = 1.0 if k == n else beta.ppf(1 - alpha/2, k+1, n-k)
    return low, high


def grouped_barplot_with_cp(
    labels,
    successes_A, totals_A,  
    successes_B, totals_B,  
    ci_on="A",              
    alpha=0.05,
    err_color=None,     
    err_linewidth=1.8,
    err_capsize=6,
    show_err_labels=True,
    err_pair_fmt = "{:.3f}-{:.3f}",
    err_top_offset_pts=2,          
    err_bottom_offset_pts=2,       
    title="Two-series proportions with Clopper–Pearson CI on one series",
    annotate_counts=False
):
    labels = list(labels)
    kA = np.asarray(successes_A, dtype=int)
    nA = np.asarray(totals_A, dtype=int)
    kB = np.asarray(successes_B, dtype=int)
    nB = np.asarray(totals_B, dtype=int)

    if not (len(labels) == len(kA) == len(nA) == len(kB) == len(nB)):
        raise ValueError("labels, successes_A, totals_A, successes_B, totals_B must match in length")

    pA = kA / nA
    pB = kB / nB

    ciA = np.array([clopper_pearson(k, n, alpha) for k, n in zip(kA, nA)])
    ciB = np.array([clopper_pearson(k, n, alpha) for k, n in zip(kB, nB)])
    lowA, highA = ciA[:, 0], ciA[:, 1]
    lowB, highB = ciB[:, 0], ciB[:, 1]

    x = np.arange(len(labels))
    width = 0.38

    fig, ax = plt.subplots(figsize=(10, 5.2))
    barsA = ax.bar(x - width/2, pA, width, label="SymbEx + Model Count Probs")
    barsB = ax.bar(x + width/2, pB, width, label="Monte Carlo Probs")

    if ci_on.upper() == "A":
        y = pA
        low, high = lowA, highA
        yerr = np.vstack([y - low, high - y])
        xpos = x - width/2
        label_ci = "Clopper-Pearson 95% CI"
    elif ci_on.upper() == "B":
        y = pB
        low, high = lowB, highB
        yerr = np.vstack([y - low, high - y])
        xpos = x + width/2
        label_ci = "Clopper-Pearson 95% CI"
    else:
        raise ValueError('ci_on must be "A" or "B"')

    eb = ax.errorbar(
        xpos, y, yerr=yerr, fmt='none',
        ecolor=err_color, elinewidth=err_linewidth, capsize=err_capsize,
        label=label_ci
    )

    ymax_needed = (np.max(high) if len(high) else 1.0) * 1.10
    ax.set_ylim(0, max(1.0, ymax_needed))

    ax.set_xticks(x, labels)
    ax.set_ylabel("Probability", fontsize=12)
    ax.set_xlabel("mutrace", fontsize=12)
    ax.set_title(title, fontsize=14)
    ax.legend()

    if ci_on.upper() != "A":
        for bar, p, k, n in zip(barsA, pA, kA, nA):
            ax.annotate(
                f"{p:.4f}" + (f"\n({k}/{n})" if annotate_counts else ""),
                xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                xytext=(0, 4), textcoords="offset points",
                ha="center", va="bottom"
            )
    if ci_on.upper() != "B":
        for bar, p, k, n in zip(barsB, pB, kB, nB):
            ax.annotate(
                f"{p:.4f}" + (f"\n({k}/{n})" if annotate_counts else ""),
               xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                xytext=(0, 4), textcoords="offset points",
                ha="center", va="bottom"
            )

    if show_err_labels:
        for xi, lo, hi in zip(xpos, low, high):
            ax.annotate(
                err_pair_fmt.format(lo,hi),
                xy=(xi, hi),
                xytext=(0, err_top_offset_pts),
                textcoords="offset points",
                ha="center", va="bottom", clip_on=True
            )

    plt.tight_layout()

    plt.savefig('tracersym_vs_tracersim_probs.pdf', format="pdf", dpi=300, bbox_inches='tight')


def barplot_with_cp(
    labels,
    successes_A, totals_A,         
    alpha=0.05,
    err_color=None,                
    err_linewidth=1.8,
    err_capsize=6,
    show_err_labels=True,
    err_pair_fmt = "{:.3f}-{:.3f}",
    err_top_offset_pts=2,          
    err_bottom_offset_pts=2,       
    title="Two-series proportions with Clopper�~@~SPearson CI on one series",
    fname="tracer_sim_probs_plot.pdf",
    annotate_counts=False
):
    labels = list(labels)
    kA = np.asarray(successes_A, dtype=int)
    nA = np.asarray(totals_A, dtype=int)

    if not (len(labels) == len(kA) == len(nA)):
        raise ValueError("labels, successes_A, totals_A must match in length")

    pA = kA / nA

    ciA = np.array([clopper_pearson(k, n, alpha) for k, n in zip(kA, nA)])
    lowA, highA = ciA[:, 0], ciA[:, 1]

    x = np.arange(len(labels))
    width = 0.38

    fig, ax = plt.subplots(figsize=(10, 5.2))
    barsA = ax.bar(x - width/2, pA, width)

    y = pA
    low, high = lowA, highA
    yerr = np.vstack([y - low, high - y])
    xpos = x - width/2
    label_ci = "Clopper-Pearson 95% CI"

    eb = ax.errorbar(
        xpos, y, yerr=yerr, fmt='none',
        ecolor=err_color, elinewidth=err_linewidth, capsize=err_capsize,
        label=label_ci
    )

    ymax_needed = (np.max(high) if len(high) else 1.0) * 1.10
    ax.set_ylim(0, max(1.0, ymax_needed))

    ax.set_xticks(x, labels)
    ax.set_ylabel("Probability", fontsize=12)
    ax.set_xlabel("mutrace", fontsize=12)
    ax.set_title(title, fontsize=14)
    ax.legend()

    if show_err_labels:
        for xi, lo, hi in zip(xpos, low, high):
            ax.annotate(
                err_pair_fmt.format(lo,hi),
                xy=(xi, hi),
                xytext=(0, err_top_offset_pts),
                textcoords="offset points",
                ha="center", va="bottom", clip_on=True
            )

    plt.tight_layout()

    plt.savefig(fname, format="pdf", dpi=300, bbox_inches='tight')
    return


def main(args):
    if len(sys.argv) < 3:
        print("Usage: python3 compute_ep_delt.py <trace_counts_dict1> <trace_counts_dict2>")
        sys.exit(1)
    
    counts_file1 = sys.argv[1]
    counts_file2 = sys.argv[2]
    
    # Compute epsilon
    with open(counts_file1) as f:
        monte_carlo_freqs_dict = json.load(f)
    
    monte_carlo_freqs = monte_carlo_freqs_dict.values()
    N = sum(monte_carlo_freqs)
    
    #print("freq: # mutraces with freq")
    #print(num_freqs)
    #print()

    threshold = N/10
    min_above_threshold = N
    num_above_threshold = 0
    for k in monte_carlo_freqs:
        if k >= threshold:
            num_above_threshold += k
            if k < min_above_threshold:
                min_above_threshold = k

    if len(monte_carlo_freqs) == 1:
        pml, pml_low, pml_high = compute_pml(N-3,N)
        epsilon = pml
        #print(f"Epsilon = {pml}") 
    elif min_above_threshold==N:
        #print(f"No trace with probability above above threshold {threshold/N}. All traces are highly leaky.")
        print(f"All \u03BCtraces have high leakage")
        return
    else:
        pml, pml_low, pml_high = compute_pml(min_above_threshold,N) 
        epsilon = pml_high
        #print(f"Epsilon = {epsilon}")

    #return 
    
    # Compute delta
    with open(counts_file2) as f:
        monte_carlo_freqs_dict = json.load(f)

    monte_carlo_freqs = monte_carlo_freqs_dict.values()
    N = sum(monte_carlo_freqs)

    probs = dict()
    num_freqs = Counter()
    for v in monte_carlo_freqs:
        num_freqs[v] += 1

    delt = 0
    for f, num_instances in num_freqs.items():
        pml, pml_lb, pml_ub = compute_pml(f, N)
        prob = f*num_instances / N
        #print(f"{num_instances} mutraces with prob {f}/{N} --> P[PML = {pml}] = {prob}]")

        # Changed this COME BACK
        if pml < epsilon:
            delt += f*num_instances

    if len(monte_carlo_freqs) == 1:
        one_minus_delta_low = 1 - 3/N
    else:
        one_minus_delta_low, one_minus_delta_high = clopper_pearson(delt, N)
        
    #print(f"Delta = {1-one_minus_delta_low}")
    #print(f"P[PML <= {epsilon}] >= 1 - delt = {1 - delt/N}")
    print(f"P[PML <= {epsilon:.4f}] >= {one_minus_delta_low:.4f}")
    return


if __name__ == "__main__":
    main(sys.argv)
