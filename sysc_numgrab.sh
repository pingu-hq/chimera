#!/usr/bin/env sh
set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 <syscall.tbl>"
    exit 1
fi

tbl="$1"
base=$(basename "$tbl")

awk -v file="$base" '
    /^[0-9]/ {
        abi = $2

        if (abi == "common")
            print $1, $3
        else if (file == "syscall_64.tbl" && abi == "64")
            print $1, $3
        else if (file == "syscall_32.tbl" && abi == "32")
            print $1, $3
    }
' "$tbl"
