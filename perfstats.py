#!/usr/bin/env python3
"""
collect_stats.py

Collect CPU and memory statistics every second and report the average
over a configurable period (default 58 seconds).

Output format (one line per metric, integer value followed by a name):
    15 CPU_SYSTEM
    20 CPU_USER
    1  CPU_WAIT
    64 CPU_IDLE
    45 MEM_USED
    12 MEM_SWAPUSED
    8  MEM_CACHE
"""

import argparse
import sys
import time
from collections import defaultdict

try:
    import psutil
except ImportError:          # pragma: no cover
    sys.stderr.write(
        "ERROR: The 'psutil' package is required. Install it with:\n"
        "    pip install psutil\n"
    )
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    """Parse command‑line arguments."""
    parser = argparse.ArgumentParser(
        description="Average CPU / memory stats over a period."
    )
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=58,
        help="Total measurement time in seconds (default: 58)",
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=1.0,
        help="Delay between successive measurements (default: 1.0 s)",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not include iowait (wait) in the output. "
             "Useful on platforms where iowait is not reported.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    duration = args.duration
    interval = args.interval
    include_iowait = not args.no_wait

    # Containers for summing the values we will later average.
    sums = defaultdict(float)
    # Counter for how many samples we actually collected (helps if we break early).
    samples = 0

    # ------------------------------------------------------------------
    # Measurement loop
    # ------------------------------------------------------------------
    try:
        for _ in range(duration):
            # ---- CPU ----------------------------------------------------
            # cpu_times_percent blocks for *interval* seconds when `interval`
            # is > 0, which gives us exactly the timing we need.
            cpu = psutil.cpu_times_percent(interval=interval, percpu=False)

            sums["CPU_USER"]   += getattr(cpu, "user", 0.0)
            sums["CPU_SYSTEM"] += getattr(cpu, "system", 0.0)
            sums["CPU_IDLE"]   += getattr(cpu, "idle", 0.0)

            if include_iowait:
                # On Linux this field is called iowait, on Windows it does not exist.
                sums["CPU_WAIT"] += getattr(cpu, "iowait", 0.0)

            # ---- MEMORY -------------------------------------------------
            vm = psutil.virtual_memory()
            swap = psutil.swap_memory()

            # Percent of RAM that is *used* (includes cache & buffers – the same
            # definition that `vm.percent` uses).
            sums["MEM_USED"] += vm.percent

            # Percent of swap that is used.
            sums["MEM_SWAPUSED"] += swap.percent

            # Cache as a % of total RAM.
            cache_percent = (vm.cached / vm.total) * 100 if vm.total else 0.0
            sums["MEM_CACHE"] += cache_percent

            samples += 1

    except KeyboardInterrupt:          # pragma: no cover
        # If the user aborts early we still report the averages of the
        # samples we have collected.
        sys.stderr.write("\nInterrupted by user – reporting partial results.\n")

    # ------------------------------------------------------------------
    # Compute averages
    # ------------------------------------------------------------------
    if samples == 0:                    # pragma: no cover
        sys.stderr.write("No samples collected – exiting.\n")
        sys.exit(1)

    def avg(key: str) -> int:
        """Return the integer‑rounded average for *key*."""
        return int(round(sums[key] / samples))

    # Build the final ordered list of lines to print.
    output_lines = [
        f"{avg('CPU_SYSTEM')} CPU_SYSTEM",
        f"{avg('CPU_USER')} CPU_USER",
        f"{avg('CPU_WAIT')} CPU_WAIT" if include_iowait else None,
        f"{avg('CPU_IDLE')} CPU_IDLE",
        f"{avg('MEM_USED')} MEM_USED",
        f"{avg('MEM_SWAPUSED')} MEM_SWAPUSED",
        f"{avg('MEM_CACHE')} MEM_CACHE",
    ]

    # Filter out the optional line that may be None.
    output_lines = [ln for ln in output_lines if ln]

    # ------------------------------------------------------------------
    # Print results
    # ------------------------------------------------------------------
    for line in output_lines:
        print(line)


if __name__ == "__main__":
    main()
