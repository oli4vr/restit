#!/bin/bash
df -m | grep '^/' | tr -d '%' | awk '{print $5,$6}' | grep -v '^$'
