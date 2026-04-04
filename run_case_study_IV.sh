#!/bin/bash
set -euo pipefail
trap 'jobs -pr | xargs -r kill; wait' EXIT

DIR="pin-leakage_function_simulation"
RESULTS_DIR="results_case_study_IV"
MAX_JOBS="${MAX_JOBS:-$(nproc 2>/dev/null || echo 4)}"
FAILED=0

mkdir -p "$RESULTS_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# Semaphore: wait until fewer than MAX_JOBS background jobs are running.
wait_for_slot() {
    while (( $(jobs -rp | wc -l) >= MAX_JOBS )); do
        wait -n 2>/dev/null || true
    done
}

# Run a simulation then immediately parse its output.
# Usage: run_and_parse <run_script> <args...> -- <log_dir> <out_file>
# The "-- <log_dir> <out_file>" separator splits sim args from metadata.
run_and_parse() {
    local args=()
    local log_dir=""
    local out_file=""

    while [[ $# -gt 0 ]]; do
        if [[ "$1" == "--" ]]; then
            shift
            log_dir="$1"; shift
            out_file="$1"; shift
            break
        fi
        args+=("$1"); shift
    done

    (
        log "START ${out_file##*/}"
        if "${args[@]}" > "$out_file" 2>&1; then
            log "PARSE ${log_dir##*/}"
            python3 "scripts/tracer_sim_parser.py" "$log_dir" > /dev/null
            log "DONE  ${log_dir##*/}"
        else
            log "FAIL  ${out_file##*/} (exit $?)"
            exit 1
        fi
    ) &
}

# Track a background job — waits for a slot before launching.
enqueue() {
    wait_for_slot
    run_and_parse "$@"
}

log "Starting case study IV with up to $MAX_JOBS parallel jobs"

# ---------- Chacha20-Poly1305 ----------
log "=== Chacha20-Poly1305 ==="
for model in mul64 cs64 cs32; do
    for round in 1 2; do
        enqueue "./${DIR}/run_chacha20.sh" "$model" "$round" "$RESULTS_DIR" \
            -- "$RESULTS_DIR/logs_chacha20poly1305_${model}_${round}" \
               "$RESULTS_DIR/out_chacha20_${model}_${round}"
    done
done

# ---------- AES-GCM ----------
log "=== AES-GCM ==="
for round in 1 2; do
    enqueue "./${DIR}/run_aes256gcm.sh" cs64 "$round" "$RESULTS_DIR" \
        -- "$RESULTS_DIR/logs_aes256gcm_cs64_${round}" \
           "$RESULTS_DIR/out_aes256gcm_cs64_${round}"
done

# ---------- Ed25519 ----------
log "=== Ed25519 ==="
for model in mul64 cs64 cs32; do
    for round in 1 2; do
        enqueue "./${DIR}/run_ed25519.sh" "$model" "$round" "$RESULTS_DIR" 100 \
            -- "$RESULTS_DIR/logs_ed25519_${model}_${round}" \
               "$RESULTS_DIR/out_ed25519_${model}_${round}"
    done
done

# ---------- Ed25519 per function ----------
log "=== Ed25519 per function ==="
for func in ge25519_p3_tobytes sc25519_muladd sc25519_reduce; do
    for round in 1 2; do
        enqueue "./${DIR}/run_ed25519_func.sh" mul64 "$func" "$round" "$RESULTS_DIR" \
            -- "$RESULTS_DIR/logs_ed25519_${func}_mul64_${round}" \
               "$RESULTS_DIR/out_ed25519_${func}_mul64_${round}"
    done
done
for round in 1 2; do
    enqueue "./${DIR}/run_ed25519_func.sh" mul64 ge25519_scalarmult_base "$round" "$RESULTS_DIR" 100 \
        -- "$RESULTS_DIR/logs_ed25519_ge25519_scalarmult_base_mul64_${round}" \
           "$RESULTS_DIR/out_ed25519_ge25519_scalarmult_base_mul64_${round}"
done

# ---------- Argon2id ----------
log "=== Argon2id ==="
for model in mul64 cs64; do
    for round in 1 2; do
        enqueue "./${DIR}/run_argon2id.sh" "$model" "$round" "$RESULTS_DIR" 50 \
            -- "$RESULTS_DIR/logs_argon2id_${model}_${round}" \
               "$RESULTS_DIR/out_argon2id_${model}_${round}"
    done
done
for round in 1 2; do
    enqueue "./${DIR}/run_argon2id.sh" cs32 "$round" "$RESULTS_DIR" \
        -- "$RESULTS_DIR/logs_argon2id_cs32_${round}" \
           "$RESULTS_DIR/out_argon2id_cs32_${round}"
done

# Wait for all simulations + parsing to complete.
log "All jobs enqueued. Waiting for completion..."
wait || FAILED=1

if (( FAILED )); then
    log "WARNING: One or more jobs failed. Results may be incomplete."
fi

# ---------- Generate Table VI ----------
log "=== Generating Table VI ==="
OUTPUT="${RESULTS_DIR}/Table_VI_case_study_4_results.log"

trace_len() {
    local f="$1"
    if [[ -f "${f}.gz" ]] && [[ ! -f "$f" ]]; then
        gunzip -k "${f}.gz"
        wc -m < "$f"
        rm -f "$f"
    else
        wc -m < "$f"
    fi
}

ep_delt() {
    python3 "scripts/tracer_sim_compute_ep_delt.py" "$1" "$2"
}

{
    echo "Chacha20-Poly1305"
    echo "mul 64 |  $(trace_len "$RESULTS_DIR/logs_chacha20poly1305_mul64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_chacha20poly1305_mul64_1/trace_counts.json" "$RESULTS_DIR/logs_chacha20poly1305_mul64_2/trace_counts.json")"
    echo "cs 64  |  $(trace_len "$RESULTS_DIR/logs_chacha20poly1305_cs64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_chacha20poly1305_cs64_1/trace_counts.json" "$RESULTS_DIR/logs_chacha20poly1305_cs64_2/trace_counts.json")"
    echo "cs 32  |  $(trace_len "$RESULTS_DIR/logs_chacha20poly1305_cs32_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_chacha20poly1305_cs32_1/trace_counts.json" "$RESULTS_DIR/logs_chacha20poly1305_cs32_2/trace_counts.json")"

    echo ""
    echo "AES-GCM"
    echo "cs 64  |  $(trace_len "$RESULTS_DIR/logs_aes256gcm_cs64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_aes256gcm_cs64_1/trace_counts.json" "$RESULTS_DIR/logs_aes256gcm_cs64_2/trace_counts.json")"

    echo ""
    echo "Ed25519"
    echo "mul 64 |  $(trace_len "$RESULTS_DIR/logs_ed25519_mul64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_ed25519_mul64_1/trace_counts.json" "$RESULTS_DIR/logs_ed25519_mul64_2/trace_counts.json")"
    echo "cs 64  |  $(trace_len "$RESULTS_DIR/logs_ed25519_cs64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_ed25519_cs64_1/trace_counts.json" "$RESULTS_DIR/logs_ed25519_cs64_2/trace_counts.json")"
    echo "cs 32  |  $(trace_len "$RESULTS_DIR/logs_ed25519_cs32_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_ed25519_cs32_1/trace_counts.json" "$RESULTS_DIR/logs_ed25519_cs32_2/trace_counts.json")"

    echo ""
    echo "Argon2id"
    echo "mul 64 |  $(trace_len "$RESULTS_DIR/logs_argon2id_mul64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_argon2id_mul64_1/trace_counts.json" "$RESULTS_DIR/logs_argon2id_mul64_2/trace_counts.json")"
    echo "cs 64  |  $(trace_len "$RESULTS_DIR/logs_argon2id_cs64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_argon2id_cs64_1/trace_counts.json" "$RESULTS_DIR/logs_argon2id_cs64_2/trace_counts.json")"
    echo "cs 32  |  $(trace_len "$RESULTS_DIR/logs_argon2id_cs32_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_argon2id_cs32_1/trace_counts.json" "$RESULTS_DIR/logs_argon2id_cs32_2/trace_counts.json")"
} > "$OUTPUT"

# ---------- Generate Table VII ----------
log "=== Generating Table VII ==="
OUTPUT="${RESULTS_DIR}/Table_VII_ed25519_leakage_by_function.log"
{
    echo "ge25519_p3_tobytes |  $(trace_len "$RESULTS_DIR/logs_ed25519_ge25519_p3_tobytes_mul64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_ed25519_ge25519_p3_tobytes_mul64_1/trace_counts.json" "$RESULTS_DIR/logs_ed25519_ge25519_p3_tobytes_mul64_2/trace_counts.json")"
    echo "sc25519_muladd |  $(trace_len "$RESULTS_DIR/logs_ed25519_sc25519_muladd_mul64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_ed25519_sc25519_muladd_mul64_1/trace_counts.json" "$RESULTS_DIR/logs_ed25519_sc25519_muladd_mul64_2/trace_counts.json")"
    echo "sc25519_reduce |  $(trace_len "$RESULTS_DIR/logs_ed25519_sc25519_reduce_mul64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_ed25519_sc25519_reduce_mul64_1/trace_counts.json" "$RESULTS_DIR/logs_ed25519_sc25519_reduce_mul64_2/trace_counts.json")"
    echo "ge25519_scalarmult_base |  $(trace_len "$RESULTS_DIR/logs_ed25519_ge25519_scalarmult_base_mul64_1/trace_0.log")  | $(ep_delt "$RESULTS_DIR/logs_ed25519_ge25519_scalarmult_base_mul64_1/trace_counts.json" "$RESULTS_DIR/logs_ed25519_ge25519_scalarmult_base_mul64_2/trace_counts.json")"
} > "$OUTPUT"

log "Complete. Results in $RESULTS_DIR"
