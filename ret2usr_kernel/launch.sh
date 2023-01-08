#!/bin/bash

# launch
timeout --foreground 300 qemu-system-x86_64 \
	-m 128M\
	-kernel ./bzImage \
	-initrd ./initramfs.cpio.gz \
	-nographic \
	-monitor none \
	-no-reboot\
	-append "console=ttyS0 nokaslr nokpti nosmap nosmep quiet panic=1 "
