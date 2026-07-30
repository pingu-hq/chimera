#!/usr/bin/env sh
set -eu

# =========
# usage
# =========

if [ $# -ne 2 ]; then
    echo "usage: $0 <syscall.tbl> <accepted_abis>"
    echo
    echo "examples:"
    echo "  $0 syscall_64.tbl common,64"
    echo "  $0 syscall_32.tbl i386"
    exit 1
fi

tbl="$1"
accepted="$2"

# =========
# extraction
# =========
#
# Extract syscall numbers and names from a Linux syscall table.
#
# Output format:
#
#   <number> <name>
#
# The accepted ABI list is a comma-separated string (e.g. "common,64").
#

awk -v accepted="$accepted" '
BEGIN {
    # Split the accepted ABI list into a lookup table.
    n = split(accepted, abi_list, ",")

    for (i = 1; i <= n; i++)
        abi_ok[abi_list[i]] = 1
}

# Ignore comments and blank lines.
!/^[0-9]/ {
    next
}

{
    abi = $2

    if (abi_ok[abi])
        print $1, $3
}
' "$tbl"
