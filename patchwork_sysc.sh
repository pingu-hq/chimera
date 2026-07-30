#!/usr/bin/env sh

# =========
# setup
# =========

mkdir -p x86 arm64

# =========
# x86/...
# =========

[ ! -e "x86/syscall_64.tbl" ] && wget "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/arch/x86/entry/syscalls/syscall_64.tbl" -O x86/syscall_64.tbl

[ ! -e "x86/syscall_32.tbl" ] && wget "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/arch/x86/entry/syscalls/syscall_32.tbl" -O x86/syscall_32.tbl

# ==========
# arm64/...
# ==========

[ ! -e "x86/syscall_32.tbl" ] && wget "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/arch/arm64/tools/syscall_32.tbl" -O arm64/syscall_32.tbl

[ ! -e "x86/syscall_64.tbl" ] && wget "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/scripts/syscall.tbl" -O arm64/syscall_64.tbl

# ==========
# embroidery
# ==========

echo "[patchwork_sysc.sh] patching x86/syscall_32.tbl"
./sysc_numgrab.sh x86/syscall_32.tbl > x86/syscall_32.dat

echo "[patchwork_sysc.sh] patching x86/syscall_64.tbl"
./sysc_numgrab.sh x86/syscall_64.tbl > x86/syscall_64.dat

echo "[patchwork_sysc.sh] patching arm64/syscall_32.tbl"
./sysc_numgrab.sh arm64/syscall_32.tbl > arm64/syscall_32.dat

echo "[patchwork_sysc.sh] patching arm64/syscall_64.tbl"
./sysc_numgrab.sh arm64/syscall_64.tbl > arm64/syscall_64.dat
