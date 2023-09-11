#!/bin/bash
if [ "$1" = "-u" ]
then
 systemctl stop restit.service
 systemctl disable restit.service
 rm /etc/systemd/system/restit.service
 systemctl daemon-reload
 rm -rf ~/.restit
 rm -rf ~/bin/restit
 exit 0
fi

B64FOUND=0
if (which base64 >/dev/null 2>&1)
then
 B64FOUND=1
fi

TMPD=/tmp/pkg.$(date +%Y%m%d%H%M).${RANDOM}
mkdir -p $TMPD

if [ "$B64FOUND" = 1 ]
then
 cat $0 | grep '^#B64#' | sed -e 's/^#B64#//' | base64 -d >${TMPD}/pkg.tgz
else
r64='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
i=0; while [ $i -lt 256 ] ; do tab[$i]=-1 ; let i=$i+1 ;done
i=0; while [ $i -lt 64 ] ; do tab[`printf "%d" "'${r64:$i:1}"`]=$i ; let i=$i+1; done
bi=0
cat $0 | grep '^#B64#' | sed -e 's/^#B64#//' | while read -n 1 x
do
 in=${tab[`printf "%d" "'$x"`]}
 if [ $in -ge 0 ]; then case $bi in
  0 ) out=$(($in<<2)); bi=6 ;;
  2 ) out=$(($out|$in)); printf \\$(printf '%03o' $(($out&255)) ); bi=0 ;;
  4 ) out=$(($out+($in>>2))); printf \\$(printf '%03o' $(($out&255)) );
  bi=0; out=$(($in<<6)); bi=2 ;;
  * ) out=$(($out+($in>>4))); printf \\$(printf '%03o' $(($out&255)) );
  bi=0; out=$(($in<<4)); bi=4 ;;
  esac fi
done >${TMPD}/pkg.tgz
fi


cd
tar -zx < ${TMPD}/pkg.tgz
rm -rf ${TMPD}

if [ "$USER" = root ]
then

cat > /etc/systemd/system/restit.service <<EOF
[Unit]
Description=restit service
After=network.target

[Service]
WorkingDirectory=/root/
ExecStart=/root/bin/restit
ExecReload=/bin/kill -HUP \$MAINPID
User=root
KillMode=process
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable restit.service
systemctl start restit.service

fi
exit
#payload
