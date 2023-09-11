#!/bin/bash
stot=$(cat /proc/meminfo | grep -i swaptotal | awk '{print $2}')
sfre=$(cat /proc/meminfo | grep -i swapfree | awk '{print $2}')

sper=$(((100*(stot-sfre))/stot))

echo $sper %SWAPUSED
