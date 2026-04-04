#!/bin/bash

BINARY="workloads/helium_eval_chacha20_poly1305"
PROG_LABEL="poly1305"
INSN_LABEL="mul"
SCRIPT="angr-leakage-function-insertion/symbolic_leakage_function_paths.py"
RESULTS_DIR="results_case_study_I"
PYTHON="python3"
RESULTS_OUTPUT=${RESULTS_DIR}/"Poly1305_tail_bound_guarantees.log"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

mkdir -p $RESULTS_DIR

log "Running TracerSym on Poly1305 with zero-skip leakage function on the second operand of multiply instructions"
LF1="zs_op2"
${PYTHON} ${SCRIPT} -b ${BINARY} --symbex -lf ${LF1} -l ${PROG_LABEL}_${INSN_LABEL}_${LF1} -o ${RESULTS_DIR} > ${RESULTS_DIR}/${PROG_LABEL}_${INSN_LABEL}_${LF1}.log 2>&1

echo "Zero-skip: $(python3 scripts/compute_tail_bound_tracer_sym.py ${RESULTS_DIR}/results_${PROG_LABEL}_${INSN_LABEL}_${LF1}_latest/results.log)" > ${RESULTS_OUTPUT}

log "Running TracerSym on Poly1305 with digit-serial leakage function on the second operand of multiply instructions"
LF2="ds_op2"
${PYTHON} ${SCRIPT} -b ${BINARY} --symbex -lf ${LF2} -l ${PROG_LABEL}_${INSN_LABEL}_${LF2} -o ${RESULTS_DIR} > ${RESULTS_DIR}/${PROG_LABEL}_${INSN_LABEL}_${LF2}.log 2>&1

echo "Digit-serial: $(python3 scripts/compute_tail_bound_tracer_sym.py ${RESULTS_DIR}/results_${PROG_LABEL}_${INSN_LABEL}_${LF2}_latest/results.log)" >> ${RESULTS_OUTPUT}

log "Wrote tail-bound guarantees for Poly1305 in ${RESULTS_OUTPUT}"

log "Generating plot"
python3 scripts/plot_pml_results.py ${RESULTS_DIR}/results_${PROG_LABEL}_${INSN_LABEL}_${LF2}_latest/results.log ${RESULTS_DIR}/results_${PROG_LABEL}_${INSN_LABEL}_${LF1}_latest/results.log ${RESULTS_DIR}/Figure_7_poly1305_ep_delt_under_two_lfs.pdf
