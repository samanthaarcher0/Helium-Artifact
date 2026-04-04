#!/bin/bash


SCRIPT="angr-leakage-function-insertion/symbolic_leakage_function_paths.py"
PYTHON="python3"

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <prog> <insn> <LF> <result_dir> [args]" >&2
  exit 1
fi

PROG_LABEL=$1
INSN_LABEL=$2
LF_LABEL=$3
RESULT_DIR=$4

BINARY="workloads/helium_eval_${PROG_LABEL}"

if [[ ! -f $BINARY ]]; then
  echo "Cannot find binary ${BINARY}"
  exit 1
fi


run_cmd="${PYTHON} ${SCRIPT} -b ${BINARY} --symbex -o ${RESULT_DIR}"

if [[ $# -gt 4 ]]; then
  ARG=$5
  run_cmd+=" --pass_args $5"
fi

TAG="${PROG_LABEL}${ARG}_${INSN_LABEL}_${LF_LABEL}"
run_cmd+=" -l ${TAG}"

LFD="lfs/${INSN_LABEL}_${LF_LABEL}.json"
if [[ -f "${LFD}" ]]; then
  run_cmd+=" -lfd ${LFD}  > ${RESULT_DIR}/out_${TAG}.log"
  echo "Found LF dict: ${LFD}"
else
  run_cmd+=" -lf ${LF_LABEL}  > ${RESULT_DIR}/out_${TAG}.log"
  echo "Did not find LF dict ${LFD}. Defaulting to LF ${LF_LABEL}"
fi

echo "Running command:\n ${run_cmd}"
eval "${run_cmd}"
