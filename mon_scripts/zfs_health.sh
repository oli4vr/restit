#!/bin/bash
## ZFS health monitoring
## Olivier Van Rompuy 2026-05-08
zpool_list_raw() {
    zpool list -H -o name,allocated,free,fragmentation -p 2>/dev/null
}

zfs_list_raw() {
    zfs list -H -o name,used,available,compression,compressratio -p 2>/dev/null
}

zpool_list_raw | while read name allocated free frag; do
    total=$((allocated + free))
    used_pct=$((allocated * 100 / total))
    size_gb=$((total / 1073741824))
    echo "$used_pct ZFS_POOL_${name}_PCT GBsize=${size_gb}GB Fragmentation=${frag}"
done

zfs_list_raw | while read name used avail comp ratio; do
    total=$((used + avail))
    used_pct=$((used * 100 / total))
    ratio_num=${ratio%x}
    
    mountpoint=$(zfs list -H -o mountpoint "$name" 2>/dev/null)
    if [ "$mountpoint" = "none" ] || [ -z "$mountpoint" ]; then
        mountpoint=""
    fi
    
    size_gb=$((total / 1073741824))
    
    if [ -n "$mountpoint" ]; then
        echo "$used_pct ZFS_FS_${name//\//_}_PCT GBsize=${size_gb}GB Mountpoint=$mountpoint Compr=$ratio_num Algorithm=$comp"
    else
        echo "$used_pct ZFS_FS_${name//\//_}_PCT GBsize=${size_gb}GB Compr=$ratio_num Algorithm=$comp"
    fi
    
done
