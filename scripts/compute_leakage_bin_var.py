import math
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import os 
from decimal import Decimal

colors = ['tab:blue', 'tab:orange', 'tab:green', 'tab:red', 'tab:purple', 'tab:brown', 'tab:pink', 'tab:gray', 'tab:olive', 'tab:cyan', 'orangered', 'turquoise', 'darkgreen', 'darkblue', 'yellowgreen', 'brown', 'coral', 'salmon', 'khaki']

def compute_leakage(PYX_00, PYX_01, probs_X):
    l = len(probs_X)
    ml = np.zeros(l)
    mi = np.zeros(l)
    pml_0 = np.zeros(l)
    pml_1 = np.zeros(l)
    pmi = np.zeros((l, 4))
    average_pml = np.zeros(l)
    ppmi = np.zeros((l, 4))
    mi_using_ppmi = np.zeros(l)
    y_entropy = np.zeros(l)
    extra_val = np.zeros(l)

    for i in range(l):
        PX_0 = probs_X[i]
        PX_1 = 1 - PX_0
        PYX_10 = 1 - PYX_00
        PYX_11 = 1 - PYX_01

        PY_0 = PYX_00*PX_0+PYX_01*PX_1
        PY_1 = PYX_10*PX_0+PYX_11*PX_1

        if PY_0 != 0 and PY_0 != 1:
            PXY_00 = PYX_00*PX_0/PY_0
            PXY_10 = PYX_01*PX_1/PY_0
        else:
            PXY_00 = PYX_00
            PXY_10 = PYX_01

        if PY_1 != 0 and PY_1 != 1:
            PXY_01 = PYX_10*PX_0/PY_1
            PXY_11 = PYX_11*PX_1/PY_1
        else: 
            PXY_01 = PYX_10
            PXY_11 = PYX_11

        assert(math.isclose(PY_0 + PY_1, 1, rel_tol=1e-9))
        assert(math.isclose(PX_0 + PX_1, 1, rel_tol=1e-9))
        assert(math.isclose(PXY_00 + PXY_10, 1, rel_tol=1e-9))
        assert(math.isclose(PXY_01 + PXY_11, 1, rel_tol=1e-9))
        assert(math.isclose(PYX_00 + PYX_10, 1, rel_tol=1e-9))
        assert(math.isclose(PYX_01 + PYX_11, 1, rel_tol=1e-9))

        #print(f"{max(PYX_00, PYX_01)} & {max(PYX_10,PYX_11)}")
        
        # Compute ML
        ml[i] = math.log2(max(PYX_00, PYX_01)+max(PYX_10,PYX_11))
        
        # Compute PML for each observation
        pml_0[i] = math.log2(max(PXY_00/PX_0, PXY_10/PX_1))
        pml_1[i] = math.log2(max(PXY_01/PX_0, PXY_11/PX_1))
       
        # Compute MI
        mi[i] = PYX_00*PX_0*math.log2(PYX_00/PY_0) + PYX_10*PX_0*math.log2(PYX_10/PY_1) + PYX_01*PX_1*math.log2(PYX_01/PY_0) + PYX_11*PX_1*math.log2(PYX_11/PY_1)
        mi_other = PXY_00*PY_0*math.log2(PXY_00/PX_0) + PXY_10*PY_0*math.log2(PXY_10/PX_1) + PXY_01*PY_1*math.log2(PXY_01/PX_0) + PXY_11*PY_1*math.log2(PXY_11/PX_1)
        assert(math.isclose(mi_other, mi[i]))

        # Compute PMI
        pmi[i,0] = math.log2(PYX_00/PY_0)
        pmi[i,1] = math.log2(PYX_01/PY_0)
        pmi[i,2] = math.log2(PYX_10/PY_1)
        pmi[i,3] = math.log2(PYX_11/PY_1)

        # Replace PMI with PML in mutual info computation
        average_pml[i] = (PY_0)*pml_0[i] + (PY_1)*pml_1[i]
        average_pml_check = (PXY_00*PY_0 + PXY_10*PY_0)*max(math.log2(PXY_00/PX_0), math.log2(PXY_10/PX_1)) + (PXY_01*PY_1+PXY_11*PY_1)*max(math.log2(PXY_01/PX_0), math.log2(PXY_11/PX_1))
        assert(math.isclose(average_pml_check,average_pml[i]))

        # Compute PPMI
        ppmi[i,0] = max(0, math.log2(PYX_00/PY_0))
        ppmi[i,1] = max(0, math.log2(PYX_01/PY_0))
        ppmi[i,2] = max(0, math.log2(PYX_10/PY_1))
        ppmi[i,3] = max(0, math.log2(PYX_11/PY_1))

        # Replace PMI with PML in mutual info computation
        mi_using_ppmi[i] = PYX_00*PX_0*ppmi[i,0] + PYX_10*PX_0*ppmi[i,2] + PYX_01*PX_1*ppmi[i,1] + PYX_11*PX_1*ppmi[i,3]

        # Entropy of Y
        y_entropy[i] = PY_0*math.log2(1/PY_0) + PY_1*math.log2(1/PY_1)

        # extra term in average PML
        extra_val[i] = -1*(PY_0*math.log2(max(PYX_00, PYX_01)) + PY_1*math.log2(max(PYX_10, PYX_11)))
        assert(math.isclose(y_entropy[i] - extra_val[i], average_pml[i]))

    return (ml, pml_0, pml_1, mi, pmi, average_pml, ppmi, mi_using_ppmi, y_entropy, extra_val)

geom_array = 1/np.geomspace(2, 8, num=10)
probs_X = np.sort(np.unique(np.concatenate((geom_array, 1-geom_array))))
PYX_00 = .75
PYX_01 = .1

# Code below allows you to specify a ML value, and get PXY_01 that satisfies
#constant_max_leakage = 1
#constant_max_leakage_exp = 2**constant_max_leakage
#print(constant_max_leakage_exp)
#for i in range(len(probs_YX)):
#    PYX_00 = probs_YX[i]
#    PYX_10 = 1 - PYX_00
#    print(f"PYX_00={PYX_00}, PYX_10={PYX_10}")
#    if constant_max_leakage_exp - PYX_00 < 1:
#        PYX_11 = constant_max_leakage_exp - PYX_00
#        PYX_01 = 1 - PYX_11
#    else:
#        PYX_01 = constant_max_leakage_exp - PYX_10
#        PYX_11 = 1 - PYX_01
#    print(f"PYX_01={PYX_01}, PYX_11={PYX_11}")
#    assert(PYX_01 >= 0)
#    assert(PYX_01 <= 1)
#    assert(PYX_11 >= 0)
#    assert(PYX_11 <= 1)
#
#    print(f"PYX_00={PYX_00}, PYX_01={PYX_01}")

ml, pml_0, pml_1, mi, pmi, average_pml, ppmi, mi_using_ppmi, y_entropy, extra_val = compute_leakage(PYX_00, PYX_01, probs_X)

## X-axis is probability of X ## 
plt.figure(1, figsize=(6, 2.9))  # Optional: Set the figure size
plt.plot(probs_X, pml_0, color=colors[0], label=f"PML: $\ell(y_1)$")
plt.plot(probs_X, pml_1, color=colors[1], label=f"PML: $\ell(y_2)$")
plt.plot(probs_X, ml, color=colors[2], label=f"Maximal Leakage", linestyle='-.')
plt.plot(probs_X, mi, color=colors[3], label=f"Mutual Information", linestyle='--')
#plt.plot(probs_X, pmi[:,0], color=colors[7], label=f"PMI obs 00")
#plt.plot(probs_X, pmi[:,1], color=colors[7], label=f"PMI obs 01")
#plt.plot(probs_X, pmi[:,2], color=colors[7], label=f"PMI obs 10")
#plt.plot(probs_X, pmi[:,3], color=colors[7], label=f"PMI obs 11")
#plt.plot(probs_X, average_pml, color=colors[7], label="Average PML over Y")
#plt.plot(probs_X, mi_using_ppmi, color=colors[8], label="Replace PMI with PPMI in MI computation")
#plt.plot(probs_X, y_entropy, color=colors[9], label="Entropy of Y")
#plt.plot(probs_X, extra_val, color=colors[10], label="Extra term in computation of average PML")
plt.ylabel('Leakage (bits)', fontsize=12)
#plt.xlabel('P(X=0)', fontsize=12)
plt.xlabel("$p$", fontsize=12)
#plt.title('PML vs. Maximal Leakage vs. Mutual Information for Binary Channel', fontsize=14)
plt.legend(loc='upper center')  
plt.grid(True)  
plt.savefig('PML_vs_ML_vs_MI_for_diff_PX.svg', format="svg", dpi=300, bbox_inches='tight')
plt.savefig('PML_vs_ML_vs_MI_for_diff_PX.png', format="png", dpi=300, bbox_inches='tight')
plt.savefig('PML_vs_ML_vs_MI_for_diff_PX.pdf', format="pdf", dpi=300, bbox_inches='tight')
