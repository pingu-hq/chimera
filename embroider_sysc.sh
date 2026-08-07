#!/usr/bin/env sh

# =========
# setup
# =========

mkdir -p data/x86 data/arm64

# =========
# x86/...
# =========

[ ! -e "data/x86/syscall_64.tbl" ] && wget "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/arch/x86/entry/syscalls/syscall_64.tbl" -O data/x86/syscall_64.tbl

[ ! -e "data/x86/syscall_32.tbl" ] && wget "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/arch/x86/entry/syscalls/syscall_32.tbl" -O data/x86/syscall_32.tbl

# ==========
# arm64/...
# ==========

[ ! -e "data/arm64/syscall_32.tbl" ] && wget "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/arch/arm64/tools/syscall_32.tbl" -O data/arm64/syscall_32.tbl

[ ! -e "data/arm64/syscall_64.tbl" ] && wget "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/scripts/syscall.tbl" -O data/arm64/syscall_64.tbl

# ==========
# embroidery
# ==========

echo "[embroider_sysc.sh] patching data/x86/syscall_32.tbl"
echo "-t>archdt" > data/x86/syscall_32.chmd
echo "# arch=x86" >> data/x86/syscall_32.chmd
echo "# bits=32" >> data/x86/syscall_32.chmd
echo "# generated=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> data/x86/syscall_32.chmd
echo >> data/x86/syscall_32.chmd
./sysc_textile.sh data/x86/syscall_32.tbl i386 >> data/x86/syscall_32.chmd

echo "[embroider_sysc.sh] patching data/x86/syscall_64.tbl"
echo "-t>archdt" > data/x86/syscall_64.chmd
echo "# arch=x86_64" >> data/x86/syscall_64.chmd
echo "# bits=64" >> data/x86/syscall_64.chmd
echo "# generated=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> data/x86/syscall_64.chmd
echo >> data/x86/syscall_64.chmd
./sysc_textile.sh data/x86/syscall_64.tbl common,64 >> data/x86/syscall_64.chmd

echo "[embroider_sysc.sh] patching data/arm64/syscall_32.tbl"
echo "-t>archdt" > data/arm64/syscall_32.chmd
echo "# arch=arm64" >> data/arm64/syscall_32.chmd
echo "# bits=32" >> data/arm64/syscall_32.chmd
echo "# generated=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> data/arm64/syscall_32.chmd
echo >> data/arm64/syscall_32.chmd
./sysc_textile.sh data/arm64/syscall_32.tbl common >> data/arm64/syscall_32.chmd

echo "[embroider_sysc.sh] patching data/arm64/syscall_64.tbl"
echo "-t>archdt" > data/arm64/syscall_64.chmd
echo "# arch=arm64" >> data/arm64/syscall_64.chmd
echo "# bits=64" >> data/arm64/syscall_64.chmd
echo "# generated=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> data/arm64/syscall_64.chmd
echo >> data/arm64/syscall_64.chmd
./sysc_textile.sh data/arm64/syscall_64.tbl common,64 >> data/arm64/syscall_64.chmd
