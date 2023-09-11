#!/bin/bash
multipath -ll | awk '{if (NF==3) print $1}' | while read pdev
do
 OLDNUMP=$(grep -w $pdev ${PCACHE}/${pdev} </dev/null 2>/dev/null | awk '{print $3}' 2>/dev/null)
 if [ "$OLDNUMP" = "" ]
 then
  OLDNUMP=0
 fi
 multipath -ll $pdev | tr -d '|\-\+\`' | grep -v policy | grep -v 'size='  | while read a ; do echo $a ; done | awk '{if (NF==6) {print $0}}' | grep 'active ready running' | wc -l | xargs echo $pdev $OLDNUMP >${PCACHE}/${pdev}.new
 RESULT=$(cat ${PCACHE}/${pdev}.new | awk '{if ($3 < $2) {print "1";} else {print "0";}}')
 echo $RESULT $(cat ${PCACHE}/${pdev}.new | awk '{print $1}' )
 if [ "$RESULT" = "HEALTHY" ]
 then
  mv ${PCACHE}/${pdev}.new ${PCACHE}/${pdev}
 fi
done
