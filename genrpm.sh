#!/bin/bash
## restit deb rpm pkg generator
## https://github.com/oli4vr/restit
## by Olivier Van Rompuy 2026
echo "restit package builder script"
echo "by Olivier Van Rompuy 2026    Westpole"
echo "###################"
chmod a+rx restit.*.sh
if test -x /usr/bin/rpmbuild
then
 rm -rf ~/rpmbuild 2>/dev/null
 cp restit.*.sh restit.sh
 chmod u+x restit.sh
 cat restit.spec.templ | sed -e 's/__RELEASE__/'$(date "+%Y %j" | awk '{printf("%02d%03d\n",$(1)-2024,$2);}')'/' >restit.spec
 echo rpmbuild --define \"_sourcedir $(pwd)\" -bb restit.spec
 rpmbuild --define "_sourcedir $(pwd)" -bb restit.spec >/dev/null 2>&1
 mv $(find ~/rpmbuild/RPMS -name '*.rpm'  | head -n1) .
 rm -rf ~/rpmbuild 2>/dev/null
 rm restit.sh
 rm restit.spec
fi
RPMF=$(ls *.rpm 2>/dev/null | head -n1)
if test -x /usr/bin/alien
then
 if [ "$RPMF" != "" ]
 then
  fakeroot alien -k --scripts --to-deb $RPMF
 fi
fi
DEBF=$(ls *.deb 2>/dev/null | head -n1)
echo "###################"
echo "Installer Package :" $(ls -tr restit.*.sh | tail)
echo "Install with : ./"$(ls -tr restit.*.sh | tail)
echo "Uninstall    : ./"$(ls -tr restit.*.sh | tail)" -u"
if [ "$RPMF" != "" ]
then
 echo "RPM package  : ${RPMF}"
fi
if [ "$DEBF" != "" ]
then
 echo "DEB package  : ${DEBF}"
fi
echo "Access via   : http://hostname:40480"

