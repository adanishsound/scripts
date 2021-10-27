#!/bin/bash
#
# host is available on 10.0.2.2
#

# port forward to the host to access guest services
FWD_OPTS=",hostfwd=tcp::8080-:8080,hostfwd=tcp::8443-:8443"

qemu-system-x86_64 -enable-kvm -display gtk \
    -cpu host -smp $(nproc) -m 4096M \
    -drive format=raw,file=qemu.img,if=virtio \
    -net nic -net user,hostname=qemu-vm${FWD_OPTS}  &> /tmp/qemu_run_os.out &

