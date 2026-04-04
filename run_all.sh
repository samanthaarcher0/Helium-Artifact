#!/bin/bash

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Running case study I"
./run_case_study_I.sh
log "Finished case study I"

log "Running case study II"
./run_case_study_II.sh
log "Finished case study II"

log "Running case study III"
./run_case_study_III.sh
log "Finished case study III"

log "Running case study IV"
./run_case_study_IV.sh
log "Finished case study IV"
