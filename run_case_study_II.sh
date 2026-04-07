#!/bin/bash

BINARY="workloads/helium_firefox_convolve"
PROG_LABEL="convolve"
INSN_LABEL="mul"
SCRIPT="angr-leakage-function-insertion/symbolic_leakage_function_paths.py"
RESULTS_DIR="results_case_study_II"
PYTHON="python3"
OUTPUT_TABLE="${RESULTS_DIR}/Table_IV_convolve_tail_bound_guarantees.log"
RUNTIME_OUTPUT="${RESULTS_DIR}/Table_III_part2_convolve_runtime_stats.log"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

mkdir -p $RESULTS_DIR

echo "Optimization | #mutraces | epsilon | delta | Tail-bound guarantee" > ${OUTPUT_TABLE}

log "Running TracerSym on Firefox's convolution with zero-skip leakage function on the second operand of multiply instructions"
LF1="zs_op2"
${PYTHON} ${SCRIPT} -b ${BINARY} --symbex -lf ${LF1} -l ${PROG_LABEL}_${INSN_LABEL}_${LF1} -o ${RESULTS_DIR} > ${RESULTS_DIR}/${PROG_LABEL}_${INSN_LABEL}_${LF1}.log 2>&1

python3 scripts/compute_tail_bound_tracer_sym.py ${RESULTS_DIR}/results_${PROG_LABEL}_${INSN_LABEL}_${LF1}_latest/results.log "Zero-skip   " >> ${OUTPUT_TABLE}


log "Running TracerSym on Firefox's convolution with digit-serial leakage function on the second operand of multiply instructions"
LF2="ds_op2"
${PYTHON} ${SCRIPT} -b ${BINARY} --symbex -lf ${LF2} -l ${PROG_LABEL}_${INSN_LABEL}_${LF2} -o ${RESULTS_DIR} > ${RESULTS_DIR}/${PROG_LABEL}_${INSN_LABEL}_${LF2}.log 2>&1

python3 scripts/compute_tail_bound_tracer_sym.py ${RESULTS_DIR}/results_${PROG_LABEL}_${INSN_LABEL}_${LF2}_latest/results.log Digit-serial >> ${OUTPUT_TABLE}

log "Generate runtime stats"
python3 scripts/tracer_sym_runtime_parser.py ${RESULTS_DIR}/${PROG_LABEL}_${INSN_LABEL}_${LF1}.log ${RESULTS_DIR}/${PROG_LABEL}_${INSN_LABEL}_${LF2}.log > ${RUNTIME_OUTPUT}
