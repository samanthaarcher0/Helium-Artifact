# Description

This artifact demonstrates leakage quantification with Helium, using both TracerSym and TracerSim to compute pointwise maximal leakage (PML) tail-bound security guarantees for multiple programs. The artifact provides a Dockerfile that builds a container image containing all required dependencies (including Python 3, the necessary Python packages, and Intel Pin), along with scripts to reproduce all four case studies presented in the paper. The artifact can be executed on any x86_64 machine with Docker, Git, and Bash support, and requires at least 32 GB of RAM and 8 GB of available disk space.

# Installation

Clone this repository:
```
git clone https://github.com/samanthaarcher0/Helium-Artifact.git
cd Helium-Artifact
```
Build the Docker image:
```
docker build -f Dockerfile -t helium_artifact .
```
After the image has been successfully built, launch the container:
```
docker run -it helium_artifact
```

# Run evaluation
All four case studies, along with their corresponding outputs and figures, can be reproduced as described in this section. In total, the full evaluation requires approximately 10 hours on a dual-socket server equipped with two Intel Xeon Gold 6226R CPUs (2.90 GHz). The system has 32 physical cores with 2-way simultaneous multithreading (64 logical CPUs) and 512 GB of RAM. However, the experiments use at most 32 GB of memory. All workloads are provided as precompiled binaries; no additional build step is required.

## Case Study I
This case study evaluates cryptographic MAC Poly1305 under two multiplication μobs functions, zero-skip and digit-serial multiplication. It takes less than 6 minutes to run. The outputs can be found in `results_case_study_I` directory. To run:
```
### In the Docker container ###
./run_case_study_I.sh
```

Outputs:
- `Poly1305_tail_bound_guarantees.log`: The log contains the two tail-bound guarantees that are discussed in the text of VII-A, one for Poly1305 under zero-skip multiplication and the other for Poly1305 under digit-serial multiplication.
- `Figure_7_poly1305_ep_delt_under_two_lfs.pdf`: Figure 7 shows all possible tail-bound guarantees of Poly1305 under the two multiply optimizations.
- `Table_III_part1_Poly1305_runtime_stats.log`: First half of Table III with TracerSym runtime and SMT/model counting query statistics.


## Case Study II
This case study evaluates the Firefox convolution SVG filter under the same two multiplication μobs functions from Case Study I. It takes less than a minute to run. The outputs can be found in the `results _case_study_II directory`. To run:
```
### In the Docker container ###
./run_case_study_II.sh
```

Generated outputs:
- `Table_IV_convolve_tail_bound_guarantees.log`: Table IV with tail-bound guarantees of Firefox’s convolution under zero-skip and digit-serial multiplication μobs functions.
- `Table_III_part2_convolve_runtime_stats.log`: Second half of Table III with TracerSym runtime and SMT/model counting query statistics.
 
## Case Study III
This case study evaluates the scalability of TracerSym, measuring the increase in runtime and number of SMT queries as the number of instrumented instructions and the number of μobs per μobs function increases. It takes 1.5 hours to run. The outputs can be found in `results_case_study_III directory`. To run:
```
### In the Docker container ###
./run_case_study_III.sh
```

Generated outputs:
- `Figure_8_scalability_eval.pdf`: Figure 8 showing TracerSym’s runtime and number of SMT queries with increasing numbers of instrumented instructions and increasing the number of μobs per μobs function, as described in §VII-C.

## Case Study IV
This last case study computes PML tail-bound guarantees using our simulation-based methodology, TracerSim, for four cryptographic programs studied in a recent work [37]. This case study takes less than 6 hours to run. Note, as TracerSim runs Monte Carlo simulations, the exact tail-bound guarantees will differ slightly between runs. However, all values should be reasonably close to those reported in §VII-D. Further, due to slight updates in our tracing Pin tool, the table’s instruction counts differ slightly, but do not meaningfully change the leakage guarantees. The outputs can be found in `results_case_study_IV directory`. To run:
```
### In the Docker container ###
./run_case_study_IV.sh
```

Generated outputs:
- `Table_VI_case_study_4_results.log`: Table VI showing tail-bound guarantees for four programs and categories of μobs functions evaluated in prior work [37].
- `Table_VII_ed25519_leakage_by_function.log`: Table VII showing the tail-bound guarantees per function for one program, Ed25519, and one category of μobs functions.
