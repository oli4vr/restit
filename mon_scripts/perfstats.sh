#!/bin/bash
# Collect CPU and memory statistics every second and report the average
# over a configurable period (default 58 seconds).
#
# Output format (one line per metric, integer value followed by a name):
#     15 CPU_SYSTEM
#     20 CPU_USER
#     1  CPU_WAIT
#     64 CPU_IDLE
#     45 MEM_USED
#     12 MEM_SWAPUSED
#     8  MEM_CACHE

set -e

# Parse command-line arguments
DURATION=58
INTERVAL=1.0
INCLUDE_WAIT=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -i|--interval)
            INTERVAL="$2"
            shift 2
            ;;
        --no-wait)
            INCLUDE_WAIT=0
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Validate duration is a number
if ! [[ "$DURATION" =~ ^[0-9]+$ ]]; then
    echo "Error: Duration must be a positive integer" >&2
    exit 1
fi

# Validate interval is a number
if ! [[ "$INTERVAL" =~ ^[0-9]+\.?[0-9]*$ ]]; then
    echo "Error: Interval must be a positive number" >&2
    exit 1
fi

# Initialize sums
CPU_USER_SUM=0
CPU_SYSTEM_SUM=0
CPU_WAIT_SUM=0
CPU_IDLE_SUM=0
MEM_USED_SUM=0
MEM_SWAPUSED_SUM=0
MEM_CACHE_SUM=0
SAMPLES=0

# Trap for Ctrl+C
cleanup() {
    echo -e "\nInterrupted by user – reporting partial results." >&2
    finalize
}
trap cleanup SIGINT

# Function to get CPU counters
get_cpu_counters() {
    local cpu_line
    
    read -r _ cpu_user cpu_nice cpu_system cpu_idle cpu_iowait cpu_irq cpu_softirq cpu_steal _ _ < /proc/stat
}

# Function to calculate CPU percentages from deltas
calc_cpu_percent() {
    local user_delta system_delta idle_delta wait_delta total_delta
    
    user_delta=$((cpu_user - prev_cpu_user))
    system_delta=$((cpu_system - prev_cpu_system))
    idle_delta=$((cpu_idle - prev_cpu_idle))
    wait_delta=$((cpu_iowait - prev_cpu_iowait))
    
    total_delta=$((user_delta + system_delta + idle_delta + wait_delta))
    
    if [[ "$total_delta" -gt 0 ]]; then
        local user_pct system_pct idle_pct wait_pct
        user_pct=$(awk "BEGIN {printf \"%.2f\", ($user_delta / $total_delta) * 100}")
        system_pct=$(awk "BEGIN {printf \"%.2f\", ($system_delta / $total_delta) * 100}")
        idle_pct=$(awk "BEGIN {printf \"%.2f\", ($idle_delta / $total_delta) * 100}")
        
        CPU_USER_SUM=$(awk "BEGIN {printf \"%.2f\", $CPU_USER_SUM + $user_pct}")
        CPU_SYSTEM_SUM=$(awk "BEGIN {printf \"%.2f\", $CPU_SYSTEM_SUM + $system_pct}")
        CPU_IDLE_SUM=$(awk "BEGIN {printf \"%.2f\", $CPU_IDLE_SUM + $idle_pct}")
        
        if [[ "$INCLUDE_WAIT" -eq 1 ]]; then
            wait_pct=$(awk "BEGIN {printf \"%.2f\", ($wait_delta / $total_delta) * 100}")
            CPU_WAIT_SUM=$(awk "BEGIN {printf \"%.2f\", $CPU_WAIT_SUM + $wait_pct}")
        fi
    fi
}

# Function to get memory info
get_mem_info() {
    local mem_total mem_free mem_cached mem_swap_total mem_swap_free
    
    mem_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    mem_free=$(awk '/^MemFree:/ {print $2}' /proc/meminfo)
    mem_cached=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
    mem_swap_total=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
    mem_swap_free=$(awk '/^SwapFree:/ {print $2}' /proc/meminfo)
    
    # MEM_USED = ((total - free) / total) * 100
    if [[ -n "$mem_total" && "$mem_total" -gt 0 ]]; then
        local mem_used_pct
        mem_used_pct=$(awk "BEGIN {printf \"%.2f\", (($mem_total - $mem_free) / $mem_total) * 100}")
        MEM_USED_SUM=$(awk "BEGIN {printf \"%.2f\", $MEM_USED_SUM + $mem_used_pct}")
    fi
    
    # MEM_CACHE = (cached / total) * 100
    if [[ -n "$mem_total" && "$mem_total" -gt 0 ]]; then
        local mem_cache_pct
        mem_cache_pct=$(awk "BEGIN {printf \"%.2f\", ($mem_cached / $mem_total) * 100}")
        MEM_CACHE_SUM=$(awk "BEGIN {printf \"%.2f\", $MEM_CACHE_SUM + $mem_cache_pct}")
    fi
    
    # MEM_SWAPUSED = ((swap_total - swap_free) / swap_total) * 100
    if [[ -n "$mem_swap_total" && "$mem_swap_total" -gt 0 ]]; then
        local mem_swapused_pct
        mem_swapused_pct=$(awk "BEGIN {printf \"%.2f\", (($mem_swap_total - $mem_swap_free) / $mem_swap_total) * 100}")
        MEM_SWAPUSED_SUM=$(awk "BEGIN {printf \"%.2f\", $MEM_SWAPUSED_SUM + $mem_swapused_pct}")
    fi
}

# Function to finalize and print results
finalize() {
    if [[ "$SAMPLES" -eq 0 ]]; then
        echo "No samples collected – exiting." >&2
        exit 1
    fi
    
    # Calculate averages and round to integers
    local cpu_system_avg cpu_user_avg cpu_wait_avg cpu_idle_avg
    local mem_used_avg mem_swapused_avg mem_cache_avg
    
    cpu_system_avg=$(awk "BEGIN {printf \"%d\", int($CPU_SYSTEM_SUM / $SAMPLES + 0.5)}")
    cpu_user_avg=$(awk "BEGIN {printf \"%d\", int($CPU_USER_SUM / $SAMPLES + 0.5)}")
    cpu_idle_avg=$(awk "BEGIN {printf \"%d\", int($CPU_IDLE_SUM / $SAMPLES + 0.5)}")
    
    mem_used_avg=$(awk "BEGIN {printf \"%d\", int($MEM_USED_SUM / $SAMPLES + 0.5)}")
    mem_swapused_avg=$(awk "BEGIN {printf \"%d\", int($MEM_SWAPUSED_SUM / $SAMPLES + 0.5)}")
    mem_cache_avg=$(awk "BEGIN {printf \"%d\", int($MEM_CACHE_SUM / $SAMPLES + 0.5)}")
    
    echo "$cpu_system_avg CPU_SYSTEM"
    echo "$cpu_user_avg CPU_USER"
    if [[ "$INCLUDE_WAIT" -eq 1 ]]; then
        cpu_wait_avg=$(awk "BEGIN {printf \"%d\", int($CPU_WAIT_SUM / $SAMPLES + 0.5)}")
        echo "$cpu_wait_avg CPU_WAIT"
    fi
    echo "$cpu_idle_avg CPU_IDLE"
    echo "$mem_used_avg MEM_USED"
    echo "$mem_swapused_avg MEM_SWAPUSED"
    echo "$mem_cache_avg MEM_CACHE"
    
    exit 0
}

# Initial CPU sample
get_cpu_counters
prev_cpu_user=$cpu_user
prev_cpu_nice=$cpu_nice
prev_cpu_system=$cpu_system
prev_cpu_idle=$cpu_idle
prev_cpu_iowait=$cpu_iowait

# Main measurement loop
for ((i = 0; i < DURATION; i++)); do
    # Wait before sampling (except for first iteration which already has baseline)
    if [[ $i -gt 0 ]]; then
        sleep "$INTERVAL"
    fi
    
    # Get new CPU counters
    get_cpu_counters
    
    # Calculate CPU percentages based on deltas
    calc_cpu_percent
    
    # Get memory info
    get_mem_info
    
    SAMPLES=$((SAMPLES + 1))
    
    # Update previous values
    prev_cpu_user=$cpu_user
    prev_cpu_nice=$cpu_nice
    prev_cpu_system=$cpu_system
    prev_cpu_idle=$cpu_idle
    prev_cpu_iowait=$cpu_iowait
done

finalize
