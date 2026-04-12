#!/bin/bash

# AMD GPU basic statistics collector

GPU_PATH="/sys/class/drm"

if [[ ! -d "$GPU_PATH" ]]; then
    echo "Error: No GPU devices found in $GPU_PATH" >&2
    exit 1
fi

for card_dir in "$GPU_PATH"/card*; do
    [[ -d "$card_dir" ]] || continue
    card_name=$(basename "$card_dir")
    gpu_index="${card_name#card}"
    [[ -f "$card_dir/device/vendor" ]] || continue
    vendor_id=$(cat "$card_dir/device/vendor" 2>/dev/null)
    vendor_id_lower=$(echo "$vendor_id" | tr '[:upper:]' '[:lower:]')
    if [[ "$vendor_id_lower" != "0x1002" ]]; then
        continue
    fi
    
    gpu_dir="$card_dir/device"
    
    # GPU percentage used
    gpu_pct="N/A"
    if [[ -f "$gpu_dir/drm/card$gpu_index/device/utilization" ]]; then
        gpu_pct=$(grep -oP 'gpu=\K\d+' "$gpu_dir/drm/card$gpu_index/device/utilization" 2>/dev/null | head -1)
    elif [[ -f "$gpu_dir/drm/card$gpu_index/device/gpu_busy_percent" ]]; then
        gpu_pct=$(cat "$gpu_dir/drm/card$gpu_index/device/gpu_busy_percent" 2>/dev/null | tr -d '\n')
    elif [[ -f "$gpu_dir/drm/card$gpu_index/device/device_perf_level" ]]; then
        gpu_pct="0"
    fi
    [[ -n "$gpu_pct" ]] || gpu_pct="N/A"
    
    # VRAM usage
    vram_pct="N/A"
    if [[ -f "$gpu_dir/mem_info_vram_used" ]] && [[ -f "$gpu_dir/mem_info_vram_total" ]]; then
        vram_used=$(cat "$gpu_dir/mem_info_vram_used" 2>/dev/null)
        vram_total=$(cat "$gpu_dir/mem_info_vram_total" 2>/dev/null)
        if [[ -n "$vram_used" ]] && [[ -n "$vram_total" ]] && [[ "$vram_total" -gt 0 ]]; then
            vram_pct=$((vram_used * 100 / vram_total))
        fi
    elif [[ -f "$gpu_dir/drm/card$gpu_index/device/mem_info_vram_used" ]] && [[ -f "$gpu_dir/drm/card$gpu_index/device/mem_info_vram_total" ]]; then
        vram_used=$(cat "$gpu_dir/drm/card$gpu_index/device/mem_info_vram_used" 2>/dev/null)
        vram_total=$(cat "$gpu_dir/drm/card$gpu_index/device/mem_info_vram_total" 2>/dev/null)
        if [[ -n "$vram_used" ]] && [[ -n "$vram_total" ]] && [[ "$vram_total" -gt 0 ]]; then
            vram_pct=$((vram_used * 100 / vram_total))
        fi
    fi
    
    # Temperature
    temp_c="N/A"
    temp_f="N/A"
    temp_raw=""
    if [[ -d "$gpu_dir/hwmon" ]]; then
        hwmon_dir=$(ls -d "$gpu_dir/hwmon/hwmon"* 2>/dev/null | head -1)
        if [[ -n "$hwmon_dir" ]] && [[ -f "$hwmon_dir/temp1_input" ]]; then
            temp_raw=$(cat "$hwmon_dir/temp1_input" 2>/dev/null)
        fi
    fi
    if [[ -z "$temp_raw" ]]; then
        if [[ -f "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/temp1_input" ]]; then
            temp_raw=$(cat "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/temp1_input" 2>/dev/null | head -1)
        elif [[ -f "$gpu_dir/drm/card$gpu_index/device/temp1_input" ]]; then
            temp_raw=$(cat "$gpu_dir/drm/card$gpu_index/device/temp1_input" 2>/dev/null)
        fi
    fi
    if [[ -n "$temp_raw" ]] && [[ "$temp_raw" =~ ^[0-9]+$ ]]; then
        temp_c=$((temp_raw / 1000))
        temp_f=$((temp_c * 9 / 5 + 32))
    fi
    
    echo "$gpu_pct GPU_PCT_USED"
    echo "$vram_pct VRAM_PCT_USED"
    echo "$temp_c GPU_TEMP_C"
    echo "$temp_f GPU_TEMP_F"
    echo "---"
done
