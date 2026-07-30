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

[ ! -e "arm64/syscall_32.tbl" ] && wget "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/arch/arm64/tools/syscall_32.tbl" -O arm64/syscall_32.tbl

[ ! -e "arm64/syscall_64.tbl" ] && wget "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/scripts/syscall.tbl" -O arm64/syscall_64.tbl

# ==========
# embroidery
# ==========

echo "[patchwork_sysc.sh] patching x86/syscall_32.tbl"
echo "# arch=x86" > x86/syscall_32.dat
echo "# bits=32" >> x86/syscall_32.dat
echo "# generated=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> x86/syscall_32.dat
echo >> x86/syscall_32.dat
./sysc_numgrab.sh x86/syscall_32.tbl i386 >> x86/syscall_32.dat

echo "[patchwork_sysc.sh] patching x86/syscall_64.tbl"
echo "# arch=x86_64" > x86/syscall_64.dat
echo "# bits=64" >> x86/syscall_64.dat
echo "# generated=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> x86/syscall_64.dat
echo >> x86/syscall_64.dat
./sysc_numgrab.sh x86/syscall_64.tbl common,64 >> x86/syscall_64.dat

echo "[patchwork_sysc.sh] patching arm64/syscall_32.tbl"
echo "# arch=arm64" > arm64/syscall_32.dat
echo "# bits=32" >> arm64/syscall_32.dat
echo "# generated=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> arm64/syscall_32.dat
echo >> arm64/syscall_32.dat
./sysc_numgrab.sh arm64/syscall_32.tbl common >> arm64/syscall_32.dat

echo "[patchwork_sysc.sh] patching arm64/syscall_64.tbl"
echo "# arch=arm64" > arm64/syscall_64.dat
echo "# bits=64" >> arm64/syscall_64.dat
echo "# generated=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> arm64/syscall_64.dat
echo >> arm64/syscall_64.dat
./sysc_numgrab.sh arm64/syscall_64.tbl common,64 >> arm64/syscall_64.dat
