#!/bin/bash

# NVIDIA GPU statistics collector using nvidia-smi

if ! command -v nvidia-smi &>/dev/null; then
    echo "Error: nvidia-smi not found" >&2
    exit 1
fi

gpu_count=$(nvidia-smi --query-gpu=count --format=csv,noheader,nounits 2>/dev/null)

if [[ "$gpu_count" -eq 0 ]]; then
    echo "Error: No NVIDIA GPUs found" >&2
    exit 1
fi

for ((gpu=0; gpu<gpu_count; gpu++)); do
    gpu_pct=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits -i "$gpu" 2>/dev/null)
    vram_used=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits -i "$gpu" 2>/dev/null)
    vram_total=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits -i "$gpu" 2>/dev/null)
    temp_c=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits -i "$gpu" 2>/dev/null)
    power_mw=$(nvidia-smi --query-gpu=power.draw --format=csv,noheader,nounits -i "$gpu" 2>/dev/null | tr -d '.')
    gpu_clock_mhz=$(nvidia-smi --query-gpu=clocks.sm --format=csv,noheader,nounits -i "$gpu" 2>/dev/null)
    vram_clock_mhz=$(nvidia-smi --query-gpu=clocks.mem --format=csv,noheader,nounits -i "$gpu" 2>/dev/null)
    fan_pct=$(nvidia-smi --query-gpu=fan.speed --format=csv,noheader,nounits -i "$gpu" 2>/dev/null)
    
    if [[ -n "$vram_used" ]] && [[ -n "$vram_total" ]] && [[ "$vram_total" -gt 0 ]]; then
        vram_pct=$((vram_used * 100 / vram_total))
    else
        vram_pct="N/A"
    fi
    
    if [[ -n "$power_mw" ]] && [[ "$power_mw" =~ ^[0-9]+$ ]]; then
        power_watts=$((power_mw / 1000))
    else
        power_watts="N/A"
    fi
    
    [[ -z "$gpu_pct" ]] && gpu_pct="N/A"
    [[ -z "$temp_c" ]] && temp_c="N/A"
    [[ -z "$gpu_clock_mhz" ]] && gpu_clock_mhz="N/A"
    [[ -z "$vram_clock_mhz" ]] && vram_clock_mhz="N/A"
    [[ -z "$fan_pct" ]] && fan_pct="N/A"
    
    temp_f=$((temp_c * 9 / 5 + 32))
    
    echo "$gpu_pct GPU_PCT_USED"
    echo "$vram_pct VRAM_PCT_USED"
    echo "$temp_c GPU_TEMP_C"
    echo "$temp_f GPU_TEMP_F"
    echo "$power_watts GPU_WATTS"
    echo "$gpu_clock_mhz GPU_CLOCK_FREQ"
    echo "$vram_clock_mhz VRAM_CLOCK_FREQ"
    echo "$fan_pct GPU_FAN_PCT"
    echo "---"
done

