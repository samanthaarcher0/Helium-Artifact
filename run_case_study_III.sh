#!/bin/bash

PROG_LABEL="img_transform_kernels"
RESULTS_DIR="results_case_study_III"
MAX_PARALLEL=${MAX_PARALLEL:-$(nproc)}

mkdir -p $RESULTS_DIR

log() { echo "[$(date '+%H:%M:%S')] $*"; }

insn_lf_tuples=("add zs_op2" "mul zs_op2" "and zs_op1" "or zs_op1" "or zs_op2" "shl zs_op1" "shr zs_op1" "xor zs_op1" "xor zs_op2")
insn_lf_tuples2=("mul ds_op2_1bit" "mul ds_op2_2bit" "mul ds_op2_4bit" "mul ds_op2_8bit")

job_count=0

run_parallel() {
  local prog=$1 insn=$2 lf=$3 results=$4 arg=$5
  log "Running TracerSym on image processing kernels for instruction: $insn, muobs function: $lf (arg=$arg)"
  ./run_symbex.sh "$prog" "$insn" "$lf" "$results" "$arg" &
  ((job_count++))
  if ((job_count >= MAX_PARALLEL)); then
    wait -n
    ((job_count--))
  fi
}

log "Launching all jobs in parallel (max $MAX_PARALLEL at a time)..."

for item in "${insn_lf_tuples[@]}"; do
  read -r insn lf <<< "$item"
  run_parallel $PROG_LABEL "$insn" "$lf" $RESULTS_DIR 2
  run_parallel $PROG_LABEL "$insn" "$lf" $RESULTS_DIR 3
done

for item in "${insn_lf_tuples2[@]}"; do
  read -r insn lf <<< "$item"
  run_parallel $PROG_LABEL "$insn" "$lf" $RESULTS_DIR 2
  run_parallel $PROG_LABEL "$insn" "$lf" $RESULTS_DIR 3
done

log "Waiting for all remaining jobs to finish..."
wait

log "Plotting results"
python3 scripts/scalability_vary_uobs.py ${RESULTS_DIR}

log "All jobs complete."
