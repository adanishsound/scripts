#!/bin/sh


qemu-system-x86_64 -enable-kvm \
    -cpu host -m 2048M \
    -drive format=raw,file=bios.bin,if=pflash \
    -drive format=raw,file=linux.img,if=virtio \
    -cdrom $1 \
    -boot d \
    -net nic -net user,hostname=qemu-vm

