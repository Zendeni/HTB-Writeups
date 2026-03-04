#!/bin/bash

# Simple Git push helper for HTB writeups

if [ -z "$1" ]; then
    echo "Usage: ./push.sh \"commit message\""
    exit 1
fi

git add .
git commit -m "$1"
git push origin main
