#!/bin/bash
. ./env_vars.sh
rm -rf *.o restit restit.*.sh 2>/dev/null
rm -rf bin 2>/dev/null
rm -rf *.deb *.rpm 2>/dev/null
rm -rf .${RESTIT_SVCNAME}