#!/bin/bash
# Tested on Ubuntu server and SLES
export PCACHE=~/.restit/mpath
mkdir -p ${PCACHE} 2>/dev/null
multipath -ll 2>/dev/null | grep -v size | grep -v policy | grep -v ' sd' | awk '{print $1}' | while read pdev
do
 OLDNUMP=$(grep -w $pdev ${PCACHE}/${pdev} </dev/null 2>/dev/null | awk '{print $3}' 2>/dev/null)
 if [ "$OLDNUMP" = "" ]
 then
  OLDNUMP=0
 fi
 multipath -ll $pdev 2>/dev/null | grep -vw $pdev | tr -d '|\-\+\`' | grep -v policy | grep -v 'size='  | while read a ; do echo $a ; done | awk '{if (NF==6) {print $0}}' | grep 'active ready running' | wc -l | xargs echo $pdev $OLDNUMP >${PCACHE}/${pdev}.new
 RESULT=$(cat ${PCACHE}/${pdev}.new | awk '{if ($3 < $2) {print "1";} else {print "0";}}')
 echo $RESULT $(cat ${PCACHE}/${pdev}.new | awk '{print $1}' )
 if [ "$RESULT" = "0" ]
 then
  mv ${PCACHE}/${pdev}.new ${PCACHE}/${pdev}
 fi
done | grep -w 1 | wc -l | xargs echo | while read a 
do
 echo $a MULTIPATH_DEVICES_ERROR

 if [ "$a" != 0 ]
 then
  for i in $(ls /sys/class/fc_host/host*/device/scsi_host/host*/scan)
  do
   echo '- - -' > $i
  done
 fi 2>/dev/null

done 2>/dev/null
