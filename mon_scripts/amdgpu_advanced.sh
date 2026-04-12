#!/bin/bash

# AMD GPU advanced statistics collector (power, clock, fan)

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
    
    # Power draw
    power_watts="N/A"
    if [[ -d "$gpu_dir/hwmon" ]]; then
        hwmon_dir=$(ls -d "$gpu_dir/hwmon/hwmon"* 2>/dev/null | head -1)
        if [[ -n "$hwmon_dir" ]] && [[ -f "$hwmon_dir/power1_input" ]]; then
            power_raw=$(cat "$hwmon_dir/power1_input" 2>/dev/null)
            if [[ -n "$power_raw" ]] && [[ "$power_raw" =~ ^[0-9]+$ ]]; then
                power_watts=$((power_raw / 1000))
            fi
        fi
    fi
    if [[ "$power_watts" == "N/A" ]]; then
        if [[ -f "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/power1_input" ]]; then
            power_raw=$(cat "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/power1_input" 2>/dev/null | head -1)
            if [[ -n "$power_raw" ]] && [[ "$power_raw" =~ ^[0-9]+$ ]]; then
                power_watts=$((power_raw / 1000))
            fi
        elif [[ -f "$gpu_dir/drm/card$gpu_index/device/power1_average" ]]; then
            power_raw=$(cat "$gpu_dir/drm/card$gpu_index/device/power1_average" 2>/dev/null)
            if [[ -n "$power_raw" ]] && [[ "$power_raw" =~ ^[0-9]+$ ]]; then
                power_watts=$((power_raw / 1000))
            fi
        fi
    fi
    
    # GPU clock
    gpu_clock_mhz="N/A"
    if [[ -f "$gpu_dir/pp_dpm_sclk" ]]; then
        gpu_clock_raw=$(grep -oP '\d+' "$gpu_dir/pp_dpm_sclk" 2>/dev/null | tail -1)
        if [[ -n "$gpu_clock_raw" ]] && [[ "$gpu_clock_raw" =~ ^[0-9]+$ ]]; then
            gpu_clock_mhz=$((gpu_clock_raw / 1000))
        fi
    elif [[ -f "$gpu_dir/drm/card$gpu_index/device/pp_dpm_sclk" ]]; then
        gpu_clock_raw=$(grep -oP '\d+' "$gpu_dir/drm/card$gpu_index/device/pp_dpm_sclk" 2>/dev/null | tail -1)
        if [[ -n "$gpu_clock_raw" ]] && [[ "$gpu_clock_raw" =~ ^[0-9]+$ ]]; then
            gpu_clock_mhz=$((gpu_clock_raw / 1000))
        fi
    elif [[ -f "$gpu_dir/drm/card$gpu_index/device/gt/gt_act_freq" ]]; then
        gpu_clock_raw=$(cat "$gpu_dir/drm/card$gpu_index/device/gt/gt_act_freq" 2>/dev/null)
        if [[ -n "$gpu_clock_raw" ]] && [[ "$gpu_clock_raw" =~ ^[0-9]+$ ]]; then
            gpu_clock_mhz=$((gpu_clock_raw / 1000))
        fi
    fi
    
    # VRAM clock
    vram_clock_mhz="N/A"
    if [[ -f "$gpu_dir/pp_dpm_mclk" ]]; then
        vram_clock_raw=$(grep -oP '\d+' "$gpu_dir/pp_dpm_mclk" 2>/dev/null | tail -1)
        if [[ -n "$vram_clock_raw" ]] && [[ "$vram_clock_raw" =~ ^[0-9]+$ ]]; then
            vram_clock_mhz=$((vram_clock_raw / 1000))
        fi
    elif [[ -f "$gpu_dir/drm/card$gpu_index/device/pp_dpm_mclk" ]]; then
        vram_clock_raw=$(grep -oP '\d+' "$gpu_dir/drm/card$gpu_index/device/pp_dpm_mclk" 2>/dev/null | tail -1)
        if [[ -n "$vram_clock_raw" ]] && [[ "$vram_clock_raw" =~ ^[0-9]+$ ]]; then
            vram_clock_mhz=$((vram_clock_raw / 1000))
        fi
    elif [[ -f "$gpu_dir/drm/card$gpu_index/device/gt/mem_act_freq" ]]; then
        vram_clock_raw=$(cat "$gpu_dir/drm/card$gpu_index/device/gt/mem_act_freq" 2>/dev/null)
        if [[ -n "$vram_clock_raw" ]] && [[ "$vram_clock_raw" =~ ^[0-9]+$ ]]; then
            vram_clock_mhz=$((vram_clock_raw / 1000))
        fi
    fi
    
    # Fan speed
    fan_pct="N/A"
    if [[ -d "$gpu_dir/hwmon" ]]; then
        hwmon_dir=$(ls -d "$gpu_dir/hwmon/hwmon"* 2>/dev/null | head -1)
        if [[ -n "$hwmon_dir" ]] && [[ -f "$hwmon_dir/fan1_input" ]] && [[ -f "$hwmon_dir/fan1_max" ]]; then
            fan_raw=$(cat "$hwmon_dir/fan1_input" 2>/dev/null)
            fan_max=$(cat "$hwmon_dir/fan1_max" 2>/dev/null)
            if [[ -n "$fan_raw" ]] && [[ -n "$fan_max" ]] && [[ "$fan_max" -gt 0 ]] && [[ "$fan_raw" =~ ^[0-9]+$ ]] && [[ "$fan_max" =~ ^[0-9]+$ ]]; then
                fan_pct=$((fan_raw * 100 / fan_max))
            fi
        fi
    fi
    if [[ "$fan_pct" == "N/A" ]]; then
        if [[ -f "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/fan1_input" ]] && [[ -f "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/fan1_max" ]]; then
            fan_raw=$(cat "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/fan1_input" 2>/dev/null | head -1)
            fan_max=$(cat "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/fan1_max" 2>/dev/null | head -1)
            if [[ -n "$fan_raw" ]] && [[ -n "$fan_max" ]] && [[ "$fan_max" -gt 0 ]] && [[ "$fan_raw" =~ ^[0-9]+$ ]] && [[ "$fan_max" =~ ^[0-9]+$ ]]; then
                fan_pct=$((fan_raw * 100 / fan_max))
            fi
        elif [[ -f "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/pwm1" ]] && [[ -f "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/pwm1_max" ]]; then
            fan_raw=$(cat "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/pwm1" 2>/dev/null | head -1)
            fan_max=$(cat "$gpu_dir/drm/card$gpu_index/device/hwmon/hwmon*/pwm1_max" 2>/dev/null | head -1)
            if [[ -n "$fan_raw" ]] && [[ -n "$fan_max" ]] && [[ "$fan_max" -gt 0 ]] && [[ "$fan_raw" =~ ^[0-9]+$ ]] && [[ "$fan_max" =~ ^[0-9]+$ ]]; then
                fan_pct=$((fan_raw * 100 / fan_max))
            fi
        fi
    fi
    
    echo "$power_watts GPU_WATTS"
    echo "$gpu_clock_mhz GPU_CLOCK_FREQ"
    echo "$vram_clock_mhz VRAM_CLOCK_FREQ"
    echo "$fan_pct GPU_FAN_PCT"
done
