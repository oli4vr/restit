#!/bin/bash
#OPATH=$(pwd)
DISTRO=$(cat /etc/os-release | head -n1 | cut -d \" -f 2 | tr -d \  )
ARCH=$(uname -p | xargs echo)
PKGNAM=restit.${DISTRO}.${ARCH}.$(date +%Y%m%d).sh

mkdir -p bin
cp restit bin/restit

cp restit.cfg .restit/
tar -c bin/restit .restit | gzip -9c > pkg.tgz

cp bundle.sh ${PKGNAM}
base64 <pkg.tgz | sed -e 's/^/#B64#/' >>${PKGNAM}

rm pkg.tgz

chmod +x ${PKGNAM}
