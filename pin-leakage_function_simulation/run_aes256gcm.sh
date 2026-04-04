#!/bin/bash
TIMEFORMAT=%R
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$1" ]; then
  echo "Specify mul64 cs64 or cs32."
  exit 1
fi

round=""
if [ "$#" -ge 2 ]; then
    echo "round $2"
    round=$2
fi

out_dir=""
if [ "$#" -ge 3 ]; then
    out_dir=$3
fi


num_trials=10000
if [ "$#" -ge 4 ]; then
    num_trials=$4
fi

runtime=0
if [ "$#" -ge 5  ] && [ $5 = "runtimes" ]; then
  echo "Saving runtimes"
  runtime=1
fi

experiment=$1
no_pin=0

case "$experiment" in
  mul64) opts="-mul64 1 -cs64 0 -cs32 0" ;;
  cs64)  opts="-mul64 0 -cs64 1 -cs32 0" ;;
  cs32)  opts="-mul64 0 -cs64 0 -cs32 1" ;;
  *)
    echo "Invalid argument: '$experiment'"
    exit 1
    ;;
esac

echo "Running $experiment"
DIR="${out_dir}/logs_aes256gcm_${experiment}_${round}"

if [ ! -d "$DIR" ]; then
  mkdir "$DIR"
  echo "Directory '$DIR' created."
else
  echo "Directory '$DIR' already exists."
  exit
fi

pw='2/krntW`$e"S`C,k9t|-ZyYH<AF)-B-(yj}.Vc.lS4q1/*N_#v+h/#y0?~QWs(w2f\<BHFu`xD/9MRwWbw}sRkBC{_rdW9NI8z^E'

if [ "$runtime" -eq 1 ]; then
  TIMES_FILE="$DIR/execution_times.txt"

  echo "Execution times for experiment: $experiment" > "$TIMES_FILE"
  echo "Started: $(date)" >> "$TIMES_FILE"
  echo "----------------------------------------" >> "$TIMES_FILE"

  for i in $(seq 0 99); do
    if [ "${no_pin:-0}" -eq 1 ]; then
      START=$(date +%s%N)
      ${SCRIPT_DIR}/../workloads/helium_eval_aesni256gcm_encrypt ${pw}
      END=$(date +%s%N)
    else
      START=$(date +%s%N)
      ${PIN_ROOT}/pin -t ${SCRIPT_DIR}/obj-intel64/TracerSim.so -start crypto_aead_aes256gcm_encrypt $opts -o ${DIR}/trace_${i}.log -- ${SCRIPT_DIR}/../workloads/helium_eval_aesni256gcm_encrypt $pw 
      END=$(date +%s%N)
    fi

    ELAPSED_MS=$(( (END - START) / 1000000 ))
    ELAPSED_S=$(echo "scale=3; $ELAPSED_MS / 1000" | bc)

    echo "Run $i: ${ELAPSED_S}s (${ELAPSED_MS}ms)" >> "$TIMES_FILE"
    echo "Run $i completed in ${ELAPSED_S}s"
  done

  echo "----------------------------------------" >> "$TIMES_FILE"
  echo "Finished: $(date)" >> "$TIMES_FILE"

  # Compute average
  AVG_MS=$(awk '
    /^Run [0-9]+:/ {
      match($0, /\(([0-9]+)ms\)/, arr);
      sum += arr[1]; count++
    }
    END {
      if (count > 0) printf "%.3f", sum / count
    }
  ' "$TIMES_FILE")

  AVG_S=$(echo "scale=3; $AVG_MS / 1000" | bc)

  echo "Average: ${AVG_S}s (${AVG_MS}ms)" >> "$TIMES_FILE"

  echo ""
  echo "----------------------------------------"
  echo "Average execution time: ${AVG_S}s (${AVG_MS}ms)"
  echo "----------------------------------------"

else
  for ((i=0; i<num_trials; i++)); do
    ${PIN_ROOT}/pin -t ${SCRIPT_DIR}/obj-intel64/TracerSim.so -start crypto_aead_aes256gcm_encrypt $opts -o ${DIR}/trace_${i}.log -- ${SCRIPT_DIR}/../workloads/helium_eval_aesni256gcm_encrypt $pw
  done
fi
