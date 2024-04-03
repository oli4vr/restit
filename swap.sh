#!/bin/bash
stot=$(cat /proc/meminfo | grep -i swaptotal | awk '{print $2}')
sfre=$(cat /proc/meminfo | grep -i swapfree | awk '{print $2}')

if [ "$stot" != "0" ]
then
 sper=$(((100*(stot-sfre))/(stot)))
 echo $sper %SWAPUSED
fi
