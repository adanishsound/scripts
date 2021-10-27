#!/bin/bash
# qemu_install_os.sh <os_Install.iso>
#
# qemu-img create qemu.img 40G
# host is available on 10.0.2.2
#

if [ -z "$1" ]; then
    echo "Usage $0 <os_install.iso>"
    exit 1
fi

qemu-system-x86_64 -enable-kvm -display gtk \
    -cpu host -smp $(nproc) -m 4096M -boot d -cdrom $1 \
    -drive format=raw,file=qemu.img,if=virtio \
    -net nic -net user,hostname=qemu-vm &> /tmp/qemu_install_os.out &

